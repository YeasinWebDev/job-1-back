const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const PORT = process.env.PORT || 8000;

const app = express();

const corsOptions = {
  origin: ["http://localhost:5173","https://job-1-one.vercel.app"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("hello world!");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;

const uri = `mongodb+srv://${username}:${password}@cluster0.0hkunxl.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
    if (err) {
      console.log(err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    const db = client.db("jobtask");
    const userCollection = db.collection("users");
    const paymentCollection = db.collection("payment");

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
        expiresIn: "1hr",
      });

      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    // Updated user registration route
    app.post("/user", async (req, res) => {
      const user = req.body;

      // Hash the PIN
      const hashedPin = await bcrypt.hash(user.pin, 10);

      const data = {
        ...user,
        pin: hashedPin,
      };

      try {
        const result = await userCollection.insertOne(data);
        res.send(result);
      } catch (error) {
        console.error("Error inserting user:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // Updated route to find user by PIN and compare provided password
    app.get("/user", verifyToken, async (req, res) => {
      const { email } = req.query;
      const result = await userCollection.findOne({ email });
      if (!result) {
        return res.status(404).send({ message: "User not found" });
      }
      res.send(result);
    });

    // Update the POST route for user login
    app.post("/login", async (req, res) => {
      const { emailOrMobile, pin } = req.body;

      if (!emailOrMobile || !pin) {
        return res.status(400).send({
          message: "Email or mobile number and password must be provided",
        });
      }

      try {
        // Find user by email or mobile number
        const user = await userCollection.findOne({
          $or: [{ email: emailOrMobile }, { mobileNumber: emailOrMobile }],
        });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        const isMatch = await bcrypt.compare(pin, user.pin);

        if (!isMatch) {
          return res.status(401).send({ message: "Invalid pin" });
        }
        return res.send(user.email);
      } catch (error) {
        console.error("Error finding user or comparing password:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // get all user in admin
    app.get("/admin/users", verifyToken, async (req, res) => {
      try {
        const users = await userCollection
          .find({ role: { $ne: "admin" } })
          .toArray();
        res.send(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // approve a user by id
    app.put("/admin/users/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const approved = req.body;
      try {
        // Retrieve the current user status
        const user = await userCollection.findOne({ _id: new ObjectId(id) });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        // Prepare the update operation
        let updateOperation = {};

        if (approved) {
          updateOperation.$set = { approved: approved.val };
          // Increment balance only if balance is 0
          if (user.balance === 0) {
            updateOperation.$inc = {
              balance: approved.role === "user" ? 40 : 10000,
            };
          }
        }

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          updateOperation
        );

        if (result.modifiedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send(result);
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // request for payment
    // cash-in
    app.post("/cashIn", verifyToken, async (req, res) => {
      const data = req.body;
      const result = await paymentCollection.insertOne(data);
      res.send(result);
    });
    // cash-out
    app.post("/cashOut", verifyToken, async (req, res) => {
      const data = req.body;
      const result = await paymentCollection.insertOne(data);
      res.send(result);
    });
    // send money
    app.post("/sendMoney", verifyToken, async (req, res) => {
      const data2 = req.body;
      const { email, toemail, amount } = req.body;

      const fromEmail = await userCollection.findOne({ email });
      const toEmail = await userCollection.findOne({ email: toemail });

      if (!fromEmail || !toEmail) {
        return res.status(404).send("One or both users not found");
      }

      // Check if fromEmail has enough balance
      if (fromEmail.balance < amount) {
        return res.status(400).send("Insufficient balance");
      }

      // Update balances
      const updatedFromEmailBalance = fromEmail.balance - amount;
      const updatedToEmailBalance = toEmail.balance + amount;

      // Update the database with new balances
      await userCollection.updateOne(
        { email },
        { $set: { balance: updatedFromEmailBalance } }
      );

      await userCollection.updateOne(
        { email: toemail },
        { $set: { balance: updatedToEmailBalance } }
      );
      const result = await paymentCollection.insertOne(data2)
      res.send(result)
    });

    // user History
    app.post("/usersHistory", verifyToken, async (req, res) => {
      const { email } = req.body;
      try {
        const payments = await paymentCollection.find({ email }).toArray();
        res.send(payments);
      } catch (error) {
        console.error("Error fetching user history:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // agency req
    app.get('/agency',verifyToken, async (req, res) => {
      const result = await paymentCollection.find({approved : false}).toArray()
      res.send(result)
    })
    app.get('/agencyHis',verifyToken, async (req, res) => {
      const result = await paymentCollection.find({approved : true}).toArray()
      res.send(result)
    })
    app.post('/cashIn/approve',verifyToken, async (req, res) => {
      const {email, amount, agencyEmail,id} = req.body
      const user = await userCollection.findOne({ email })
      const agency = await userCollection.findOne({ email:agencyEmail })

      // Update balances
      const updatedAgencyBalance = agency.balance - amount;
      const updatedUserBalance = user.balance + amount;

      // Update the database with new balances
      await userCollection.updateOne(
        { email },
        { $set: { balance: updatedUserBalance } }
      );

      await userCollection.updateOne(
        { email: agencyEmail },
        { $set: { balance: updatedAgencyBalance } }
      );

     const datastatus= await paymentCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { approved: true } }
      );
      
      res.send(datastatus)
    })
    app.post('/cashOut/approve',verifyToken, async (req, res) => {
      const {email, amount, agencyEmail,id} = req.body
      const user = await userCollection.findOne({ email })
      const agency = await userCollection.findOne({ email:agencyEmail })

      // Update balances
      const updatedAgencyBalance = agency.balance + amount;
      const updatedUserBalance = user.balance - amount;

      // Update the database with new balances
      await userCollection.updateOne(
        { email },
        { $set: { balance: updatedUserBalance } }
      );

      await userCollection.updateOne(
        { email: agencyEmail },
        { $set: { balance: updatedAgencyBalance } }
      );

     const datastatus= await paymentCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { approved: true } }
      );
      
      res.send(datastatus)
    })

    // await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);
