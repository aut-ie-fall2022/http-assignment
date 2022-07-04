const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const app = express();

app.get('/api/v1', async (req, res) => {
    try {
        let token = '';
        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith('Bearer')
        ) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies.jwt) {
            token = req.cookies.jwt;
        }

        if (!token) {
            return res.status(401).json({
                status: 'fail', 
                message: 'You are not logged in! Please log in to get access.'
            })
        }
        const decoded = await promisify(jwt.verify)(token, 'ArashAlaei12345678');
        const { data }= await axios.get('http://localhost:80/api/v1');
        res.status(200).json({
            status: 'success', 
            message: data.message
        })
    } catch (error) {
        res.status(500).json({
            status: 'fail', 
            error
        })
    }


});

const PORT = 8081;
app.listen(PORT, () => {
    console.log(`Proxy is listening on PORT: ${PORT}`);
})