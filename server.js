const express=require('express');
const mongoose=require('mongoose');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcrypt');
const dotenv=require('dotenv');

const { faker } = require('@faker-js/faker');
function generateRandomUser() {
  return {avatar: faker.image.avatar(),}}

dotenv.config();
const User=require('./models/User');
const cors = require('cors');

const app=express();
const port=3000;

app.use(express.json())
app.use(cors())

mongoose.connect(process.env.MONGODB_URL,{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(()=>{console.log('connected to mongo Db......')}).catch((e)=>{console.log('Mongo connection error',e)})

app.listen(port,()=>{console.log('Listning on port'+port)})
app.get('/', (req, res) => {
  res.send('Working fine');
});

app.post('/api/signup', async(req,res)=>{
    try{
        const {name,email,password}=req.body
        const existingUser= await User.findOne({email})
        console.log(existingUser)
        if(existingUser){
            return res.status(500).json({message:'Email allready in use'})
        }
        const hasedPassword= await bcrypt.hash(password,10)
        const randomPic = generateRandomUser();
        const newUser=new User({
            name,email,password:hasedPassword,avatar:randomPic.avatar,role:'user',
        })
        await newUser.save()
        res.status(200).json({message:'User created Successfully'})
    }
    catch(error){
        console.log('error during signup',error)
        res.status(500).json({message:'server error during signup'})

    }
})
app.post('/api/admin/signup', async(req,res)=>{
    try{
        const {name,email,password}=req.body
        const existingUser= await User.findOne({email})
        console.log(existingUser)
        if(existingUser){
            return res.status(500).json({message:'Email allready in use'})
        }
        const hasedPassword= await bcrypt.hash(password,10)
        const randomPic = generateRandomUser();
        const newUser=new User({
            name,email,password:hasedPassword,avatar:randomPic.avatar,role: 'admin',
        })
        await newUser.save()
        res.status(200).json({message:'User created Successfully'})
    }
    catch(error){
        console.log('error during signup',error)
        res.status(500).json({message:'server error during signup'})

    }
})


app.post('/api/signin', async(req,res)=>{
    try{
        const {email,password}=req.body
        const user= await User.findOne({email})
        if(!user){
            return  res.status(401).json({message:'Invalid email or password'})
        }
        const ismatch= await bcrypt.compare(password,user.password)
        if(!ismatch){
            return  res.status(401).json({message:'Invalid email or password'})
        }

        const token =jwt.sign({userId:user._id,email:user.email},process.env.SECRET_KEY,{expiresIn:'1h'})


        res.json({token,user:{email:user.email}})
        
    }
    catch(error){
        console.log('error during signup',error)
        res.status(500).json({message:'server error during signup'})

    }
})

app.put('/api/profile/update', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { name, password } = req.body;

    const updateFields = {};
    if (name) updateFields.name = name;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateFields.password = hashedPassword;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateFields, {
      new: true,
      select: '-password',
    });

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ message: 'Server error while updating profile' });
  }
});



function authenticateToken(req,res,next){
    const authHeaders=req.headers['authorization']
    const token = authHeaders && authHeaders.split(' ')[1]
    if(!token){
            return  res.status(401).json({message:'No token provided, authorization denied'})
        }

    try{
        const decode= jwt.verify(token,process.env.SECRET_KEY)
        req.user=decode
        next()
    }
    catch(err){
        return  res.status(403).json({message:'Invalid or expired token'})
    }
}
app.get('/api/profile',authenticateToken, async(req,res)=>{
    try{
        const userId=req.user.userId
        const user=await User.findById(userId).select("-password")
         if(!user){
            return  res.status(404).json({message:'User not found'})
        }
        return res.json({user});
    }
    catch(error){
        console.log('fetching profile error',error)
        res.status(500).json({message:'Server error'})

    }
})