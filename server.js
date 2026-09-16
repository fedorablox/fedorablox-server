const express=require("express");
const bcrypt=require("bcryptjs");
const {Pool}=require("pg");
const app=express();
app.use((req,res,next)=>{
  const origin=req.headers.origin;
  if(origin === "https://site.fedorablox.workers.dev" || origin === "http://localhost" || origin === "http://127.0.0.1") {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if(req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json());
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}}):null;
async function init(){if(!pool)return;await pool.query(`CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,username VARCHAR(20) UNIQUE NOT NULL,password_hash TEXT NOT NULL,birthday DATE NOT NULL,email TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);}
app.get("/",(_q,r)=>r.json({service:"FedoraBlox",status:"online"}));
app.get("/health",(_q,r)=>r.json({ok:true,database:!!pool}));
app.post("/signup/v1",async(req,res)=>{try{const{username,password,birthday,email}=req.body||{};if(!username||!password||!birthday)return res.status(400).json({success:false,message:"Missing required fields."});if(!/^[A-Za-z0-9_]{3,20}$/.test(username))return res.status(400).json({success:false,message:"Invalid username."});if(password.length<8)return res.status(400).json({success:false,message:"Password must be at least 8 characters."});if(!pool)return res.status(503).json({success:false,message:"Database is not connected yet."});const x=await pool.query("SELECT id FROM users WHERE LOWER(username)=LOWER($1)",[username]);if(x.rowCount)return res.status(409).json({success:false,message:"Username is already taken."});const hash=await bcrypt.hash(password,12);const y=await pool.query("INSERT INTO users(username,password_hash,birthday,email) VALUES($1,$2,$3,$4) RETURNING id,username,birthday,email,created_at",[username,hash,birthday,email||null]);res.status(201).json({success:true,user:y.rows[0]});}catch(e){console.error(e);res.status(500).json({success:false,message:"Server error."});}});
app.post("/v2/login",async(req,res)=>{try{const{username,password}=req.body||{};if(!pool)return res.status(503).json({success:false,message:"Database is not connected yet."});const x=await pool.query("SELECT id,username,password_hash FROM users WHERE LOWER(username)=LOWER($1)",[username]);if(!x.rowCount)return res.status(401).json({success:false,message:"Invalid username or password."});const u=x.rows[0];if(!await bcrypt.compare(password||"",u.password_hash))return res.status(401).json({success:false,message:"Invalid username or password."});res.json({success:true,user:{id:u.id,username:u.username}});}catch(e){console.error(e);res.status(500).json({success:false,message:"Server error."});}});
init().then(()=>{const port=process.env.PORT||10000;app.listen(port,()=>console.log("FedoraBlox API listening on "+port));}).catch(e=>{console.error(e);process.exit(1);});
