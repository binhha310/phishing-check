import express from 'express'
import * as fs from 'fs'
import * as fsPromise from 'fs/promises'
import formidable from 'formidable'
import path from 'path'
const __dirname = path.resolve()

const router = express.Router()
const blobToFile = function (theBlob, fileName){
    theBlob.lastModifiedDate = new Date();
    theBlob.name = fileName;
    return theBlob;
}

const writeFile = filename => function(file) {
  return fsPromise.writeFile(filename, Buffer.from(new Uint8Array(file)))
                  .then(function(filename) {
                    console.log(`Write file ${filename} successfully!`)
                  })
                  .catch(function(error){
                    console.log(error)
                  })
}

router.post('/', function(req, res) {
  const model = 'model.json'
  const weight = 'model.weights.bin'
  const getPath = file_name => `${__dirname}/model/${file_name}`

  const form = formidable({ multiples: true })
  const writeModel = writeFile(getPath(model))
  const writeWeight = writeFile(getPath(weight))
  form.parse(req, async (err, fields, files) => {
    await writeModel(files[model])
    await writeWeight(files[weight])
  })
})

export default router
