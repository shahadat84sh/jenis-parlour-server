const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_KEY);
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express()
const jwt = require("jsonwebtoken");
require("dotenv").config()
const port = process.env.PORT || 5000;

// middleware
app.use(cors())
app.use(express.json());

const verifyJWT = (req, res, next) =>{
  const authorization = req.headers.authorization;
  if(!authorization){
    return res.status(401).send({ error:true, message: 'Unauthorized access' })
  }
  const token = authorization.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) =>{
    if(err){
      return res.status(402).send({error:true, message:"Unauthorized user access"})
    }
    req.decoded = decoded;
    next()
  })
}

const verifyToken = ( req, res, next ) =>{
  if(!req.headers.authorization){
    return res.status(401).send({message:'unauthorized access'})
  }
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) =>{
    if(err){
      return res.status(401).send({message:'unauthorized access'})
    }
    req.decoded = decoded;
    next()
  })
}

// WITH MONGODB CODE START

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xu7lgvl.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)

    const reviewCollection = client.db('parlourDB').collection('reviews')
    const usersCollection = client.db("parlourDB").collection("users");
    const paymentCollection = client.db("parlourDB").collection("payments");
    const cartCollection = client.db("parlourDB").collection("carts");

    app.post("/jwt", (req, res) =>{
      const user = req.body;
      const token =jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      })
      res.send({token})
    })

    const verifyAdmin = async (req, res, next) =>{
      const email = req.decoded.email;
      const query = {email: email}
      const user = await usersCollection.findOne(query)
      const isAdmin = user?.role === "admin";
      if(!isAdmin){
        return res.status(403).send({message:'Forbidden access'})
      }
      next()
    }
    app.get('/users', verifyJWT, verifyAdmin,  async(req, res) =>{
      const result = await usersCollection.findOne().toArray()
      res.send(result);
    })

    // user related apis
    app.post('/users', async(req, res) =>{
      const user = req.body;
      const query = {email: user.email}
      const existingUser = await usersCollection.findOne(query);
      if(existingUser){
        return res.send({message:'User already Logged in'})
      }
      const result = await usersCollection.insertOne(user)
      res.send(result)
    })
    /***
     * firstlayer verifyJWT
     * secondly email? == same
     */
    app.get('/users/admin/:email', verifyJWT, async( req, res ) =>{
      const email = req.params.email;
      if(req.decoded.email !== email){
        res.send({admin:false})
      }
      const query = {email: email};
      const user = await usersCollection.findOne(query)
      const result = {admin: user?.role == "admin"}
      res.send({ result })
    })

    app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) =>{
      const id = req.params.id;
      const filter = {_id: new ObjectId(id)};
      const updateDoc ={
        $set:{
          role: 'admin'
        },
      };
      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    })
    app.delete('/users/:id', verifyToken, verifyAdmin, async(req, res) =>{
      const id = req.params.id;
      const query = { _id: new ObjectId(id)}
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    })
    app.post('/carts', async(req, res) =>{
      const item = req.body;
      const result = await cartCollection.insertOne(item);
      res.send(result);
    } )
    app.get('/carts', verifyJWT, async(req, res) =>{
      const email = req.query.email;
      if(!email){
        res.send([])
      }
      const decodedEmail = req.decoded.email;
      if(email !== decodedEmail){
        res.status(403).send({error:true, message:'forbidden access'})
      }
      const query = {email:email};
      const result = await cartCollection.find(query).toArray()
      res.send(result)
    })
    app.delete('/carts/:id', async(req, res) =>{
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await cartCollection.deleteOne(query)
      res.send(result)
    })

    app.get('/review', async (req, res) =>{
        const result = await reviewCollection.find().toArray();
        res.send(result);
    })

    // payment related info
    app.post('create-payment-intent', async(req,res) =>{
      const {price} = req.body;
      const amount = parseInt(price *100);
      console.log(amount, 'amount inside the intent');
      const paymentIntent = await stripe.paymentIntent.create({
        amount:amount,
        currency: 'usd',
        payment_method_types:['card']
      });
      res.send({
        clientSecret:paymentIntent.client_secret
      })
    })
    app.get('/payments/:email', verifyToken, async(req, res) =>{
      const query = {email: req.params.email}
      if(req.params.email !== req.decoded.email){
        return res.status(403).send({message:'forbidden access'})
      }
      const result = await paymentCollection.find(query).toArray()
      res.send(result)
    })
    app.post('/payments', async (req, res) =>{
      const payment = req.body;
      const paymentResult = await paymentCollection.insertOne(payment)
      console.log('paymentInfo', payment);
      const query = {
        _id:{
          $in: payment.cartIds.map(id => new ObjectId(id))
        }
      }
      const deleteResult = await cartCollection.deleteMany(query)
      res.send({paymentResult, deleteResult})
    })

    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// WITH MONGODB CODE END
app.get('/', (req, res) =>{
    res.send('Jeni apar parlour')
})

app.listen(port, () =>{
    console.log(`Jenis parlorur running on port ${port}`);
})