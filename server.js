const express = require('express');
const neo4j = require('neo4j-driver');
const cors = require('cors');
var bodyParser = require('body-parser')
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();


const app = express();
const port = process.env.PORT;

app.use(cors({
  origin: process.env.CORS_ORIGINS.split(',')
}));

app.use(bodyParser.json())

const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
);

const JWT_SECRET = process.env.JWT_SECRET;

const session = driver.session();


app.get('/tasks', async (req, res) => {
  const { 
    locality = "", 
    skills = "", 
    startDate = "", 
    endDate = "", 
    status = "",
    token = "" 
  } = req.query;

  let localityFilter = "";
  if (locality) {
    const localities = locality.split(",").map(loc => loc.trim()).filter(loc => loc !== "");
    if (localities.length > 0) {
      localityFilter = `AND (${localities.map(loc => `p.addressLocality CONTAINS "${loc}"`).join(" OR ")})`;
    }
  }

  let skillsFilter = "";
  if (skills) {
    const sk = skills.split(",").map(skill => skill.trim()).filter(skill => skill !== "");
    if (sk.length > 0) {
      skillsFilter = `AND (${sk.map(skill => `s.name CONTAINS "${skill}"`).join(" OR ")})`;
    }
  }

  const startDateFilter = startDate ? `AND t.startDate >= datetime("${startDate}")` : "";
  const endDateFilter = endDate ? `AND t.endDate <= datetime("${endDate}")` : "";
  const statusFilter = status ? `AND t.status CONTAINS "${status}"` : "";

  try {
    const session = driver.session();

    const query = `
      MATCH (t:Task)
      OPTIONAL MATCH (group:Group)-[:ASSIGNED_TO]->(t)
      OPTIONAL MATCH (volunteerInGroup:Volunteer)-[:IS_PART_OF]->(group)
      OPTIONAL MATCH (volunteer:Volunteer)-[:ASSIGNED_TO]->(t)
      WITH t, 
          count(DISTINCT volunteerInGroup) + count(DISTINCT volunteer) AS assignedCount
      OPTIONAL MATCH (t)-[:REQUIRES_SKILL]->(s:Skill)
      MATCH (t)-[:HAS_LOCATION]->(p:Place)
      WHERE 1=1
          ${localityFilter}
          ${skillsFilter}
          ${startDateFilter}
          ${endDateFilter}
          ${statusFilter}
      RETURN t.name AS taskName, 
             s.name AS skills, 
             p.addressLocality AS location, 
             t.startDate AS startDate, 
             t.endDate AS endDate, 
             t.neededPersons as neededPersons,
             COALESCE(t.tolerance, 0) AS tolerance,
             assignedCount AS assignedPersons,
             t.neededPersons - assignedCount AS missingAssignments,
             t.status AS status,
             ID(t) as tid,
             ID(p) as pid
    `;

    const result = await session.run(query);

    let tasks = result.records.map(record => ({
      name: record.get('taskName'),
      skills: record.get('skills'),
      location: record.get('location'),
      startDate: record.get('startDate').toStandardDate(), 
      endDate: record.get('endDate').toStandardDate(), 
      neededPersons: record.get('neededPersons').toNumber(),
      assignedPersons: record.get('assignedPersons').toNumber(),
      missingAssignments: record.get('missingAssignments').toNumber(),
      tolerance: record.get('tolerance').toNumber(),
      status: record.get('status'),
      tid: record.get('tid').toNumber(),
      pid: record.get('pid').toNumber(),
    }));

    // Check how the user is assigned to each task
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      const email = decoded.email;

      for (let task of tasks) {
        const assignmentQuery = `
          MATCH (t:Task)
          WHERE ID(t) = $tid
          OPTIONAL MATCH (v:Volunteer {email: $email})-[:ASSIGNED_TO]->(t)
          OPTIONAL MATCH (group:Group)-[:ASSIGNED_TO]->(t)
          OPTIONAL MATCH (vg:Volunteer {email: $email})-[:IS_PART_OF]->(group)
          RETURN v IS NOT NULL AS isDirectlyAssigned, vg IS NOT NULL AS isGroupAssigned
        `;

        const assignmentResult = await session.run(assignmentQuery, { email, tid: task.tid });

        if (assignmentResult.records.length > 0) {
          const record = assignmentResult.records[0];
          const isDirectlyAssigned = record.get("isDirectlyAssigned");
          const isGroupAssigned = record.get("isGroupAssigned");
          task.isAssigned = isDirectlyAssigned || isGroupAssigned;
          task.isGroupAssigned = isGroupAssigned;
        } else {
          task.isAssigned = false;
          task.isGroupAssigned = false;
        }
      }
    }

    res.json({ tasks });
  } catch (error) {
    console.error("Error fetching tasks:", error);
    res.status(500).send({ error: "Error fetching tasks" });
  } finally {
    await session.close();
  }
});

app.get("/task-suggestions", async (req, res) => {
  const { query = "" } = req.query;
  const session = driver.session();

  try {
    const result = await session.run(
      `MATCH (t:Task)
       WHERE t.name CONTAINS $query
       RETURN t.name AS taskName`,
      { query }
    );

    const tasks = result.records.map(record => record.get("taskName"));
    res.json({ tasks });
  } catch (error) {
    console.error("Error fetching task suggestions:", error);
    res.status(500).json({ error: "Error fetching suggestions" });
  } finally {
    await session.close();
  }
});

app.get("/admin-query", async (req, res) => {
  const { taskName = "", matchType = "exact" } = req.query;
  const session = driver.session();

  try {
    const baseQuery = `
      MATCH (t:Task)-[:REQUIRES_SKILL]->(required:Skill)
      ${matchType === 'related' ? `
        OPTIONAL MATCH (required)-[:BROADER_THAN*0..3]->(narrower:Skill)
        OPTIONAL MATCH (required)<-[:BROADER_THAN]-(broader:Skill|SkillGroup)-[:BROADER_THAN*0..1]->(grouped:Skill)
      ` : 'WITH t, required, NULL as broader, NULL AS narrower, NULL AS grouped'}
      WITH t, required, 
        apoc.coll.toSet(
          CASE WHEN '${matchType}' = 'exact' 
            THEN [required] 
            ELSE COLLECT(DISTINCT narrower) + COLLECT(DISTINCT grouped) + COLLECT(DISTINCT broader) + [required] 
          END
        ) AS skillsToMatch
      UNWIND skillsToMatch AS s
      MATCH (v:Volunteer)-[:HAS_SKILL]->(s)
      MATCH (t)-[:HAS_LOCATION]->(p:Place)
      WHERE p.addressLocality IN apoc.convert.fromJsonList(v.locationAvailability)
        AND any(interval IN apoc.convert.fromJsonList(v.availability)
              WHERE datetime(interval.start) <= t.startDate AND datetime(interval.end) >= t.endDate)
        AND NOT (v)-[:ASSIGNED_TO]->(t)
        ${taskName ? `AND t.name CONTAINS $taskName` : ""}
        AND NOT EXISTS {
          (v)-[:IS_PART_OF]->(:Group)-[:ASSIGNED_TO]->(t)
        }
      WITH t, v, required, s,
        CASE
          WHEN s = required THEN 'exact'
          WHEN EXISTS((required)-[:BROADER_THAN*]->(s)) THEN 'narrower'
          WHEN EXISTS((required)<-[:BROADER_THAN]-(s)) THEN 'broader'
          ELSE 'group'
        END AS matchType
      
      OPTIONAL MATCH (assignedVolunteer:Volunteer)-[:ASSIGNED_TO]->(t)
      OPTIONAL MATCH (group:Group)-[:ASSIGNED_TO]->(t)
      OPTIONAL MATCH (volunteerInGroup:Volunteer)-[:IS_PART_OF]->(group)
      
      WITH t, v, 
          count(DISTINCT assignedVolunteer) + count(DISTINCT volunteerInGroup) AS assignedCount,
          apoc.coll.toSet(collect(assignedVolunteer) + collect(volunteerInGroup)) AS assignedVolunteers,
          COLLECT({
            skill: s.name,
            type: matchType
          }) AS matchedSkills,
          REDUCE(
            bestType = 'group', 
            mt IN COLLECT(DISTINCT matchType) | 
              CASE 
                WHEN mt = 'exact' THEN 'exact'
                WHEN mt = 'narrower' AND bestType <> 'exact' THEN 'narrower'
                WHEN mt = 'broader' AND NOT bestType IN ['exact', 'narrower'] THEN 'broader'
                ELSE bestType
              END
          ) AS bestMatchType

 
      WITH t, v, assignedCount, assignedVolunteers, matchedSkills, bestMatchType,
        REDUCE(s = [], av IN assignedVolunteers |
          s + CASE 
              WHEN EXISTS { MATCH (av)-[w2:WORKED_ON]->(task1:Task),
                                  (v)-[w1:WORKED_ON]->(task1)
                            WHERE w1.startTime < w2.endTime 
                              AND w2.startTime < w1.endTime }
              THEN [av.givenName + " " + av.familyName]
              ELSE [] 
              END
        ) AS workedWithNamesRaw
        
      RETURN 
        t.name AS taskName,
        t.description AS taskDescription,
        t.startDate AS taskStartDate,
        t.endDate AS taskEndDate,
        t.status AS taskStatus,
        t.neededPersons AS taskNeededPersons,
        id(t) AS taskId,
        v.givenName AS givenName,
        v.familyName AS familyName,
        v.email AS email,
        v.telephone AS telephone,
        v.availability AS availability,
        v.locationAvailability AS locationAvailability,
        id(v) AS vid,
        assignedCount AS assignedPersons,
        t.neededPersons - assignedCount AS missingAssignments,
        assignedVolunteers,
        [name IN workedWithNamesRaw WHERE name IS NOT NULL] AS workedWithNames,
        matchedSkills,
        bestMatchType
        ORDER BY 
        CASE bestMatchType
          WHEN 'exact' THEN 1
          WHEN 'narrower' THEN 2
          WHEN 'broader' THEN 3
          ELSE 4
        END
    `;

    const result = await session.run(baseQuery, { taskName, matchType });

    const results = result.records.map((record) => ({
      taskId: record.get("taskId").toNumber(),
      taskName: record.get("taskName"),
      taskDescription: record.get("taskDescription"),
      taskStartDate: record.get("taskStartDate").toStandardDate(),
      taskEndDate: record.get("taskEndDate").toStandardDate(),
      taskStatus: record.get("taskStatus"),
      taskNeededPersons: record.get("taskNeededPersons").toNumber(),
      assignedPersons: record.get("assignedPersons").toNumber(),
      volunteers: [{
        id: record.get("vid").toNumber(),
        givenName: record.get("givenName"),
        familyName: record.get("familyName"),
        email: record.get("email"),
        telephone: record.get("telephone"),
        availability: record.get("availability"),
        locationAvailability: record.get("locationAvailability"),
        workedWith: record.get("workedWithNames") || [],
        matchedSkills: record.get("matchedSkills"),
        bestMatchType: record.get("bestMatchType")
      }],
      assignedVolunteers: record.get("assignedVolunteers").map((v) => ({
        id: v.identity.toNumber(),
        givenName: v.properties.givenName,
        familyName: v.properties.familyName,
        email: v.properties.email,
        telephone: v.properties.telephone,
        availability: v.properties.availability,
        locationAvailability: v.properties.locationAvailability,
      })),
    }));

    const groupedResults = results.reduce((acc, curr) => {
      const existingTask = acc.find((task) => task.taskId === curr.taskId);
      if (existingTask) {
        curr.volunteers.forEach((volunteer) => {
          const existingVolunteer = existingTask.volunteers.find(v => v.id === volunteer.id);
          if (!existingVolunteer) {
            existingTask.volunteers.push(volunteer);
          } else {
            existingVolunteer.workedWith = [...new Set([
              ...existingVolunteer.workedWith, 
              ...volunteer.workedWith
            ])];
          }
        });
      } else {
        acc.push(curr);
      }
      return acc;
    }, []);

    res.json({ results: groupedResults });
  } catch (error) {
    console.error("Error executing query:", error);
    res.status(500).json({ error: "An error occurred while executing the query." });
  } finally {
    await session.close();
  }
});


app.post("/tasks", async (req, res) => {
  const session = driver.session();
  const {
    name,
    description,
    startDate,
    endDate,
    status,
    priority,
    remarks,
    location,
    skills,
    neededPersons,
    tolerance,
    categoryId,
  } = req.body;


  try {
    const result = await session.executeWrite(tx => tx.run(
      `MATCH (c:TaskCategory WHERE id(c) = $categoryId)
       CREATE (t:Task {
         name: $name,
         description: $description,
         startDate: datetime($startDate),
         endDate: datetime($endDate),
         dateCreated: datetime(),
         status: $status,
         priority: $priority,
         remarks: $remarks,
         neededPersons: $neededPersons,
         tolerance: $tolerance
       })
       CREATE (t)-[:IS_INSTANCE_OF]->(c)
       WITH t
       MERGE (p:Place {
         latitude: $latitude,
         longitude: $longitude,
         addressLocality: $addressLocality,
         postalCode: $postalCode,
         streetAddress: $streetAddress,
         addressRegion: $addressRegion,
         addressCountry: $addressCountry
       })
       CREATE (t)-[:HAS_LOCATION]->(p)
       WITH t
       UNWIND $skills AS skillName
       MATCH (s:Skill {name: skillName})
       MERGE (t)-[:REQUIRES_SKILL]->(s)
       RETURN id(t) as taskId`,
      {
        name,
        description,
        startDate,
        endDate,
        status,
        priority,
        remarks,
        neededPersons: neo4j.int(neededPersons),
        tolerance: neo4j.int(tolerance),
        categoryId: neo4j.int(categoryId),
        skills: skills,
        ...location,
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      }
    ));

    if (result.records.length === 0) {
      return res.status(400).json({ error: "Failed to create task" });
    }



    res.status(201).json({ 
      taskId: result.records[0].get("taskId").toString()
    });
  } catch (error) {
    console.error("Error creating task:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    await session.close();
  }
});

app.get("/task-categories", async (req, res) => {
  const session = driver.session();
  try {
    const result = await session.run(
      "MATCH (c:TaskCategory) RETURN id(c) as id, c.name as name"
    );
    const categories = result.records.map(record => ({
      id: record.get("id").toNumber(),
      name: record.get("name")
    }));
    res.json(categories);
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    await session.close();
  }
});


app.get("/volunteer/:vid", async (req, res) => {
  const { vid } = req.params;
  const session = driver.session();

  try {
    const query = `
      MATCH (v:Volunteer)
      WHERE ID(v) = $vid
      RETURN v.givenName AS name, 
             v.familyName AS familyName, 
             v.email AS email, 
             v.telephone AS telephone
    `;
    const result = await session.run(query, { vid: parseInt(vid, 10)  });

    const record = result.records[0];

    if (record) {
      res.json({
        name: record.get("name"),
        familyName: record.get("familyName"),
        email: record.get("email"),
        telephone: record.get("telephone"),
      });
    } else {
      res.status(404).json({ error: "Volunteer not found" });
    }
  } catch (error) {
    console.error("Error fetching volunteer details:", error);
    res.status(500).json({ error: "Error fetching volunteer details" });
  }
  finally {
    await session.close();
  }
});

app.get("/place/:pid", async (req, res) => {
  const { pid } = req.params;
  const session = driver.session();

  try {
    const query = `
      MATCH (p:Place)
      WHERE ID(p) = $pid
      RETURN p.latitude AS latitude,
             p.longitude AS longitude,
             p.addressLocality AS addressLocality,
             p.postalCode AS postalCode,
             p.streetAddress AS streetAddress,
             p.addressRegion AS addressRegion,
             p.addressCountry AS addressCountry
    `;
    const result = await session.run(query, { pid: parseInt(pid, 10) });

    const record = result.records[0];

    if (record) {
      res.json({
        latitude: record.get("latitude"),
        longitude: record.get("longitude"),
        addressLocality: record.get("addressLocality"),
        postalCode: record.get("postalCode"),
        streetAddress: record.get("streetAddress"),
        addressRegion: record.get("addressRegion"),
        addressCountry: record.get("addressCountry"),
      });
    } else {
      res.status(404).json({ error: "Place not found" });
    }
  } catch (error) {
    console.error("Error fetching place details:", error);
    res.status(500).json({ error: "Error fetching place details" });
  } finally {
    session.close();
  }
});

app.post("/signup", async (req, res) => {
  const {givenName, familyName, email, gender, telephone, password} = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const session = driver.session();


    const query = `
      CREATE (v:Volunteer {
        givenName: $givenName,
        familyName: $familyName,
        email: $email,
        gender: $gender,
        telephone: $telephone,
        password: $hashedPassword,
        dateCreated: datetime(),
        streak: 0,
        goal: 30
      })
      RETURN v.email
    `;

    const result = await session.run(query, {
      givenName,
      familyName,
      email,
      gender,
      telephone,
      hashedPassword,
    });

    res.status(201).json({ message: "User successfully created.", email: result.records[0].get("v.email") });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Error during signup.", error: error.message });
  } finally {
    await session.close();
  }
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and Password are required." });
  }

  try {
    const session = driver.session();

    const query = `
      MATCH (u) 
      WHERE (u:Volunteer OR u:Coordinator) AND u.email = $email
      RETURN u.password AS hashedPassword, u, labels(u) AS labels
    `;

    const result = await session.run(query, { email });

    if (result.records.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const record = result.records[0];
    const hashedPassword = record.get("hashedPassword");
    const isPasswordValid = await bcrypt.compare(password, hashedPassword);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Wrong password." });
    }

    const user = record.get("u").properties;
    const labels = record.get("labels");
    const role = labels.includes("Coordinator") ? "coordinator" : "volunteer";

    const token = jwt.sign({ 
      email: user.email,
      role: role
    }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ 
      message: "Login successful.", 
      token, 
      user: {
        ...user,
        role: role
      }
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Error during login.", error: error.message });
  } finally {
    await session.close();
  }
});

app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();
    const result = await session.run(
      `MATCH (v:Volunteer {email: $email})
       RETURN v.givenName AS givenName,
              v.familyName AS familyName,
              v.email AS email,
              v.gender AS gender,
              v.telephone AS telephone,
              apoc.convert.fromJsonList(v.availability) AS availability,
              apoc.convert.fromJsonList(v.locationAvailability) AS locationAvailability,
              v.streak AS streak
              `,
      { email }
    );

    if (result.records.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const record = result.records[0];

    const responseData = {
      givenName: record.get("givenName"),
      familyName: record.get("familyName"),
      email: record.get("email"),
      gender: record.get("gender"),
      telephone: record.get("telephone"),
      availability: record.get("availability") || [],
      locationAvailability: record.get("locationAvailability") || [],
      streak: record.get("streak").toNumber()
    };

    res.json({ user: responseData });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ error: "Error fetching profile" });
  }  finally {
    await session.close();
  }
});
app.put("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const formData = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();
    const query = `
      MATCH (v:Volunteer {email: $email})
      SET v.givenName = $givenName,
          v.familyName = $familyName,
          v.gender = $gender,
          v.telephone = $telephone,
          v.availability = $availability,
          v.locationAvailability = $locationAvailability
      WITH v
      OPTIONAL MATCH (v)-[r:HAS_SKILL]->()
      DELETE r
      WITH v
      UNWIND $skills AS skillName
      MERGE (s:Skill {name: skillName})
      MERGE (v)-[:HAS_SKILL]->(s)
      RETURN v
    `;

    const params = {
      email,
      givenName: formData.givenName || "",
      familyName: formData.familyName || "",
      gender: formData.gender || "",
      telephone: formData.telephone || "",
      availability: JSON.stringify(formData.availability || []),
      locationAvailability: JSON.stringify(formData.locationAvailability || []),
      skills: formData.skills || []
    };

    await session.run(query, params);
    res.status(200).json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Error updating profile" });
  } finally {
    await session.close();
  }
});

app.put('/goal', async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { goal } = req.body; 


  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();
    const query = `
      MATCH (v:Volunteer {email: $email})
      SET v.goal = $goal
      RETURN v
    `;

    const params = { email, goal: goal || 30 };
    const result = await session.run(query, params);

    res.status(200).json({ message: 'Goal updated successfully', data: result.records[0].get('v') });
  } catch (err) {
    console.error('Error saving goal:', err);
    res.status(500).json({ message: 'Error saving goal' });
  }  finally {
    await session.close();
  }
});

app.post("/assign-volunteer", async (req, res) => {

  const { vid, tid } = req.body;

  const session = driver.session();

  try {
    if(vid){

      const query = `
        MATCH (v:Volunteer)
        MATCH (t:Task)
        WHERE ID(t) = $tid AND ID(v) = $vid
        MERGE (v)-[:ASSIGNED_TO]->(t)
        `;
      await session.run(query, { vid, tid });
      
    } else {
      const token = req.headers.authorization?.split(" ")[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      const email = decoded.email;

      const query = `
        MATCH (v:Volunteer {email: $email})
        MATCH (t:Task)
        WHERE ID(t) = $tid
        MERGE (v)-[:ASSIGNED_TO]->(t)
        `;
      await session.run(query, { email, tid });
    }
    res.status(200).json({ message: "Volunteer successfully assigned to task." });
  } catch (error) {
    console.error("Error assigning volunteer to task:", error);
    res.status(500).json({ error: "An error occurred while assigning volunteer to task." });
  } finally {
    await session.close();
  }
});

app.post("/remove-volunteer", async (req, res) => {
  const { vid, tid } = req.body;
  const session = driver.session();

  try {
    if (vid) {
      const query = `
        MATCH (v:Volunteer)-[r:ASSIGNED_TO]->(t:Task)
        WHERE ID(t) = $tid AND ID(v) = $vid
        DELETE r
      `;
      await session.run(query, { vid, tid });
    } else {
      const token = req.headers.authorization?.split(" ")[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      const email = decoded.email;

      const query = `
        MATCH (v:Volunteer {email: $email})-[r:ASSIGNED_TO]->(t:Task)
        WHERE ID(t) = $tid
        DELETE r
      `;
      await session.run(query, { email, tid });
    }

    res.status(200).json({ message: "Volunteer successfully removed from task." });
  } catch (error) {
    console.error("Error removing volunteer from task:", error);
    res.status(500).json({ error: "An error occurred while removing volunteer from task." });
  } finally {
    await session.close();
  }
});



app.get('/goal', async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];


  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();

    const result = await session.run(
      `
      MATCH (v:Volunteer {email: $email})
      RETURN v.goal AS goal
      `,
      { email }
    );

    if (result.records.length === 0) {
      return res.status(404).json({ message: 'Volunteer not found' });
    }

    const user = result.records[0];


    const goal = user.get('goal').toNumber(); 
    res.status(200).json({ goal });
  } catch (err) {
    console.error('Error retrieving goal:', err);
    res.status(500).json({ message: 'Error retrieving goal' });
  }  finally {
    await session.close();
  }
});

app.get("/leaderboard/groups", async (req, res) => {
  try {
    const session = driver.session();

    const query = `
      MATCH (g:Group)-[:ASSIGNED_TO]->(t:Task)
      RETURN g.name AS groupName, COUNT(t) AS taskCount
      ORDER BY taskCount DESC LIMIT 5
    `;

    const result = await session.run(query);

    const leaderboard = result.records.map((record) => ({
      groupName: record.get("groupName"),
      taskCount: record.get("taskCount").toNumber(),
    }));

    res.status(200).json({ leaderboard });
  } catch (error) {
    console.error("Error fetching group leaderboard:", error);
    res.status(500).json({ error: "An error occurred while fetching group leaderboard" });
  } finally {
    await session.close();
  }
});

app.get("/leaderboard/volunteers", async (req, res) => {
  try {
    const session = driver.session();

    const query = `
      MATCH (v:Volunteer)-[w:WORKED_ON]->(:Task)
      RETURN v.familyName as volunteerName, SUM(w.duration) AS totalHours 
      ORDER BY totalHours DESC LIMIT 5 
    `;

    const result = await session.run(query);

    const leaderboard = result.records.map((record) => ({
      volunteerName: record.get("volunteerName"),
      totalHours: record.get("totalHours"),
    }));

    res.status(200).json({ leaderboard });
  } catch (error) {
    console.error("Error fetching volunteer leaderboard:", error);
    res.status(500).json({ error: "An error occurred while fetching volunteer leaderboard" });
  } finally {
    await session.close();
  }
});

app.get("/user-skills", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided." });
  }

  let session;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    session = driver.session();
    
    const result = await session.run(
      `
      MATCH (v:Volunteer {email: $email})-[:HAS_SKILL]->(s:Skill)
      RETURN s.name AS skillName
      `,
      { email }
    );

    const skills = result.records.map((record) => record.get("skillName"));
    res.json({ skills });

  } catch (error) {
    console.error("Error in /user-skills:", error);

    res.status(500).json({ message: "An error occurred while fetching user skills." });

  } finally {
    if (session) {
      await session.close();
    }
  }
});


app.post("/log-work", async (req, res) => {
  const session = driver.session();
  const { taskId, startTime, endTime, duration } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const result = await session.run(
      `MATCH (v:Volunteer {email: $email})
       MATCH (t:Task)
       WHERE ID(t) = $taskId
       CREATE (v)-[w:WORKED_ON]->(t)
       SET w.startTime = datetime($startTime),
           w.endTime = datetime($endTime),
           w.duration = $duration
       RETURN w`,
      {
        email,
        taskId: neo4j.int(taskId),
        startTime,
        endTime,
        duration: parseFloat(duration),
      }
    );

    if (result.records.length === 0) {
      return res.status(400).json({ error: "Failed to log work" });
    }

    res.status(200).json({ message: "Work logged successfully" });
  } catch (error) {
    console.error("Error logging work:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    await session.close();
  }
});

app.get("/user-locs", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();

    try {
      const result = await session.run(
        `
        MATCH (v:Volunteer {email: $email})
        RETURN apoc.convert.fromJsonList(v.locationAvailability) AS locs
        `,
        { email }
      );

      const locs = result.records.length > 0 ? result.records[0].get("locs") : [];

      res.json({ locs });
    } catch (queryError) {
      console.error("Neo4j Query Error:", queryError);
      res.status(500).json({ message: "Error fetching user locations." });
    } finally {
      await session.close();
    }
  } catch (error) {
    res.status(401).json({ message: "Invalid token.", error: error.message });
  }
});





app.get("/awards", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const session = driver.session();

    try {
      const result = await session.run(
        `
        MATCH (v:Volunteer {email: $email})-[w:WORKED_ON]->(:Task)
        RETURN COALESCE(SUM(w.duration), 0) AS totalHours
        `,
        { email }
      );

      if (result.records.length === 0) {
        return res.status(404).json({ message: "Benutzer nicht gefunden." });
      }

      const user = result.records[0].toObject();
      const totalHours = user.totalHours?.toNumber ? user.totalHours.toNumber() : user.totalHours;

      res.json({ totalHours });
    } catch (queryError) {
      console.error("Fehler bei der Neo4j-Abfrage:", queryError);
      res.status(500).json({ message: "Fehler beim Abrufen der Benutzerdaten." });
    } finally {
      await session.close();
    }
  } catch (error) {
    res.status(401).json({ message: "Token ungültig.", error: error.message });
  }
});


app.get("/leaderboard/streaks", async (req, res) => {
  try {
    const session = driver.session();

    const query = `
      MATCH (v:Volunteer) 
      RETURN v.familyName as volunteerName, v.streak as streak
      ORDER BY streak DESC
      LIMIT 5
    `;

    const result = await session.run(query);

    const leaderboard = result.records.map((record) => ({
      volunteerName: record.get("volunteerName"),
      streak: record.get("streak").toNumber(),
    }));

    res.status(200).json({ leaderboard });
  } catch (error) {
    console.error("Error fetching volunteer leaderboard:", error);
    res.status(500).json({ error: "An error occurred while fetching volunteer leaderboard" });
  } finally {
    await session.close();
  }
});

app.get("/skills", async (req, res) => {
  const { query = "" } = req.query;
  const session = driver.session();

  try {
    const result = await session.run(
      `MATCH (s:Skill)
       WHERE 
         toLower(s.name) CONTAINS toLower($query) OR
         any(label IN s.altLabels WHERE toLower(label) CONTAINS toLower($query))
       RETURN DISTINCT s.name AS name
       LIMIT 50`,
      { query }
    );

    const skills = result.records.map(record => record.get("name"));

    res.json({ skills });
  } catch (error) {
    console.error("Error fetching skills:", error);
    res.status(500).json({ error: "Error fetching skills" });
  } finally {
    await session.close();
  }
});

app.get('/check-leader', async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const session = driver.session();

    const result = await session.run(`
      MATCH (v:Volunteer {email: $email})-[:IS_PART_OF {leads: true}]->(g:Group)
      OPTIONAL MATCH (vt:Volunteer)-[:IS_PART_OF]->(g)
      RETURN count(*) > 0 as isLeader, COUNT(vt) as groupSize
    `, { email: decoded.email });

    const isLeader = result.records[0].get('isLeader');
    const groupSize = result.records[0].get('groupSize').toNumber();  

    res.json({ 
      isLeader,
      groupSize
    });
  } catch (error) {
    console.error("Leadership check failed:", error);
    res.status(500).json({ error: "Leadership check failed" });
  }
});


app.post("/assign-group", async (req, res) => {
  const { tid } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  const session = driver.session();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    const groupQuery = `
      MATCH (v:Volunteer {email: $email})-[:IS_PART_OF {leads: true}]->(g:Group)
      OPTIONAL MATCH (vt:Volunteer)-[:IS_PART_OF]->(g)
      WITH g, COUNT(vt) AS groupSize
      RETURN g, groupSize
    `;
    const groupResult = await session.run(groupQuery, { email });
    if (groupResult.records.length === 0) {
      return res.status(403).json({ error: "Not a leader of any group." });
    }
    const groupRecord = groupResult.records[0];
    const group = groupRecord.get('g');
    const groupSize = groupRecord.get('groupSize').toNumber();

    const taskQuery = `
      MATCH (t:Task)
      WHERE ID(t) = $tid
      OPTIONAL MATCH (g:Group)-[:ASSIGNED_TO]->(t)
      OPTIONAL MATCH (v:Volunteer)-[:IS_PART_OF]->(g)
      OPTIONAL MATCH (vInd:Volunteer)-[:ASSIGNED_TO]->(t)
      WITH t, 
          COUNT(DISTINCT v) + COUNT(DISTINCT vInd) AS assigned,
          t.neededPersons AS needed,
          COALESCE(t.tolerance, 0) AS tolerance
      RETURN assigned, needed, tolerance
    `;
    const taskResult = await session.run(taskQuery, { tid: Number(tid) });
    if (taskResult.records.length === 0) {
      return res.status(404).json({ error: "Task not found." });
    }
    const taskRecord = taskResult.records[0];
    const assigned = taskRecord.get('assigned').toNumber();
    const needed = taskRecord.get('needed').toNumber();
    const tolerance = taskRecord.get('tolerance').toNumber();

    if (assigned + groupSize > needed + tolerance) {
      return res.status(400).json({ error: "Task capacity exceeded." });
    }

    const groupId = group.identity.toNumber();
    const taskId = Number(tid);

    await session.run(
      `
      MATCH (g:Group) WHERE ID(g) = $gid
      MATCH (t:Task) WHERE ID(t) = $tid
      MERGE (g)-[:ASSIGNED_TO]->(t)
      `,
      { gid: groupId, tid: taskId }
    );

    res.status(200).json({ message: "Group assigned successfully." });
  } catch (error) {
    console.error("Error assigning group:", error);
    res.status(500).json({ error: "Internal server error." });
  } finally {
    await session.close();
  }
});


app.post("/remove-group", async (req, res) => {
  const { tid } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  const session = driver.session();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = decoded.email;

    await session.run(`
      MATCH (v:Volunteer {email: $email})-[:IS_PART_OF {leads: true}]->(g:Group)
      MATCH (g)-[r:ASSIGNED_TO]->(t:Task)
      WHERE ID(t) = $tid
      DELETE r
    `, { email, tid });

    res.status(200).json({ message: "Group removed successfully." });
  } catch (error) {
    console.error("Error removing group:", error);
    res.status(500).json({ error: "Internal server error." });
  } finally {
    await session.close();
  }
});


// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});

process.on('SIGTERM', () => {
  session.close();
  driver.close();
});