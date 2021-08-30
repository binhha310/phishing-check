import express from 'express'
import * as fs from 'fs'
import * as fsPromise from 'fs/promises'
import * as tf from '@tensorflow/tfjs-node'
import {ObjectID} from 'bson'
import { replace, compose, trim, zipObj } from 'ramda'
import getInfo from '../whois.js'
import getFeatures from '../utils/features.js'
const router = express.Router()
//const getFeatures = require('./model/features')
const toTitleCase = function (str) {
    return str.replace(
        /\w\S*/g,
        function(txt) {
            return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
        }
    );
}

const humanizeSnake = compose(trim, replace(/_/g, ' '))
const snakeToTitle = compose(toTitleCase, humanizeSnake)

const model_name = 'model'
const path = `file://model/${model_name}.json`
const model = await tf.loadLayersModel(path)

const features_name = ['HAVING_IP_ADDRESS', 'URL_LENGTH', 'SHORTINING_SERVICE', 'HAVING_AT_SYMBOL', 'DOUBLE_SLASH_REDIRECTING', 'PREFIX_SUFFIX', 'HAVING_SUB_DOMAIN', 'SSLFINAL_STATE', 'DOMAIN_REGISTERATION_LENGTH', 'FAVICON', 'PORT', 'HTTPS_TOKEN', 'REQUEST_URL', 'URL_OF_ANCHOR', 'LINKS_IN_TAGS', 'SFH', 'SUBMITTING_TO_EMAIL', 'ABNORMAL_URL', 'REDIRECT','ON_MOUSEOVER', 'RIGHTCLICK', 'POPUPWIDNOW', 'IFRAME', 'AGE_OF_DOMAIN', 'DNSRECORD', 'WEB_TRAFFIC', 'PAGE_RANK', 'GOOGLE_INDEX', 'LINKS_POINTING_TO_PAGE', 'STATISTICAL_REPORT']

const readData = function() {
    return fsPromise
        .readFile('./databases.json', 'utf-8')
        .then(function(data){
            return JSON.parse(data)
        })
        .catch(function(error){
            console.log(error)
        })
}

const writeData = function(array) {
    const data = JSON.stringify(array)	
    fs.writeFile('./databases.json', data, 'utf8', (err) => {
        if (err) {
            console.log(`Error writing file: ${err}`);
        }
    })
}

const saveDatabase = async function(e) {
    const data = await readData()
    data.shift()
    data.push(e)
    writeData(data)
}

router.get('/', async (req, res) => {
    res.json(await readData())
})

router.post('/', async (req, res) => {
    const url = req.body.url

    const features = await getFeatures(url)
    const zipped = zipObj(features_name, features)
    const sorted_features = features_name.sort().map(key => zipped[key])

    console.log(zipped)
    const info = await getInfo(url)

    const feature_tensor = tf.tensor(sorted_features, [1, 30])
    const a = model.predict(feature_tensor)
    const [[disposition]] = await a.array()

    const result = {
        _id: new ObjectID(),
        disposition: disposition,
        date: new Date(),
        url: url,
        country: info[snakeToTitle('tech_country')] ||'-',
    }

    res.json(result)
    saveDatabase(result)
})

export default router
