import express from 'express'
import {loginUser, registerUser, signin} from "../controllers/userControllers.js";



const router = express.Router()

router.post("/signup",registerUser)
router.post("/signin",loginUser)

export default router