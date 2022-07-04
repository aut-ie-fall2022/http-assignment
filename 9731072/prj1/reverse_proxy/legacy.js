const express = require('express');

const app = express();

app.get('/api/v1', (req, res) => {
    res.status(200).json({
        status: 'success', 
        message: 'Hello World!'
    })
});

const PORT = 80;
app.listen(PORT, () => {
    console.log(`Server is listening on PORT: ${PORT}`);
})