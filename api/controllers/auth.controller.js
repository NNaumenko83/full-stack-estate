import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import prisma from "../lib/prisma.js";

export const register = async (req, res) => {
    //db operations
    const { username, email, password } = req.body;
    
    try {
        
        const  hashedPassword = await bcrypt.hash(password, 10)
        console.log('hashedPassword:', hashedPassword)
        
            // CREATE A NEW USER AND SAVE TO DB
            const newUser = await prisma.user.create({
                data: {
                    username, email, password:hashedPassword
                }
            })
    } catch (error) {
        console.log(error)
        res.status(500).json({status:500, message:"Failed to create user!"})
        
    }
  

   res.status(201).json("User created successfully")
   
}
 

export const login = async (req, res) => {    
    const { username, password } = req.body;

    try {

        const user = await prisma.user.findUnique(
            {
                where: {
                    username
                }
            }
        )

        if (!user) { 
            return res.status(401).json({status:404, message:"Invalid Credentials!"})
        }
        // CHECK IF THE USER EXISTS
        
        const isPasswordValid = await bcrypt.compare(password, user.password)
        
        if (!isPasswordValid) {
            return res.status(401).json({status:404, message:"Invalid Credentials!"})
        }

        // res.setHeader("Set-Cookie", "test=" + "myValue").json("Success")
        const age = 1000 * 60 * 60 * 24 * 7

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY, {expiresIn: age})
        console.log('token:', token)

        
        res.cookie("token", token, {
            httpOnly: true,
            // secure: true
            maxAge:age
        }).status(200).json({ status: 200, message: "Login successful"})

    // GENERATE COOKIE TOKEN AND SEND TO THE USER
        
    } catch (error) {
        console.log('error:', error)
        res.status(500).json({status:500, message:"Failed to login!"})
        
    }
   
}
 


export const logout = (req, res) => {
    //db operations
 }