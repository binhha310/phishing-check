import express from 'express'
import apiRoute from './routes/apiRoute.js'
import modelRoute from './routes/modelRoute.js'
import cors from 'cors'

const app = express()

app.use(cors())
app.use(express.json())
app.use('/api', apiRoute)
app.use('/upload', modelRoute)
app.listen(3001)
