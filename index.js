const router = require('express').Router()
const fs = require('fs')
const { MSquery } = require("../model")
const httpCode = require('../resource/httpCode')
const bcrypt = require("bcryptjs")
const Subscription = require("./subscription")
const Detect = require("./detect")


router.post('/signup', async (req, res) => {
    try {
        // test for black request
        if (!req.body.Name || !req.body.Email || !req.body.Password) {
            res.status(httpCode.FORBIDDEN).send()
            return
        }

        req.body.Email = req.body.Email.toLowerCase()
        // test for existed Email
        const test = await MSquery(`SELECT * FROM member WHERE Email="${req.body.Email}"`)
        if (test.length > 0) {
            res.status(httpCode.DUPLICATED).send()
            return
        }

        //Calculating the hash string against password
        let salt = await bcrypt.genSalt(10)
        let Password = await bcrypt.hash(req.body.Password, salt)

        const result = await MSquery(`INSERT INTO member SET Name="${req.body.Name}", Email = "${req.body.Email}", Password="${Password}", Connects="5"`)
        if (result.affectedRows > 0) {
            res.status(httpCode.SUCCESS).send()
        } else res.status(httpCode.SERVER_ERROR).send()

    } catch (err) {
        console.log("Error: ", err)
    }
})

router.post("/signin", async (req, res) => {
    try {

        if (!req.body.Email || !req.body.Password) {
            res.status(httpCode.FORBIDDEN).send()
            return
        }

        req.body.Email = req.body.Email.toLowerCase()

        let user = await MSquery(`SELECT * FROM member WHERE Email="${req.body.Email}"`)

        if (user.length < 1) {
            res.status(httpCode.NOTHING).send()
            return
        }
        if (await bcrypt.compare(req.body.Password, user[0]["Password"]))
            res.status(httpCode.SUCCESS).send({ id: user[0].ID, Password: user[0].Password })
        else
            res.status(httpCode.NOT_MATCHED).send()

        return
    } catch (error) {
        console.log("Error: ", error)
    }
})

router.post("/signin-gmail-user", async (req, res) => {
    try {
        let user = await MSquery(`SELECT * FROM member WHERE Email="${req.body.email}"`)
        if (user.length) {
            res.status(httpCode.SUCCESS).send({ id: user[0].ID })
        } else {
            let save = await MSquery(`INSERT INTO member SET Name="${req.body.name}", Email="${req.body.email}"`)
            if (save.affectedRows) {
                res.status(httpCode.SUCCESS).send({ id: save.insertId })
            }
            else res.status(httpCode.QUERY_ERROR).send()
        }
    } catch (err) {
        console.log(err)
        res.status(httpCode.SERVER_ERROR).send()
    }
})

router.use("/subscription", Subscription)
router.use("/detect", Detect)
module.exports = router