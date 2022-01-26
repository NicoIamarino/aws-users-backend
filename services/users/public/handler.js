
const aws = require('aws-sdk') 

const cognitoIdentityServiceProvider = new aws.CognitoIdentityServiceProvider({ region: 'us-east-1' })

exports.register = async (event, context,callback) => {

    let statusCode = null;
    let responseMessage = null
    const reqBody = JSON.parse(event.body)

    const params = {
        ClientId: process.env.CLIENT_ID,
        Password: reqBody.password,
        Username: reqBody.email,
        UserAttributes: [
            {
                Name: 'name',
                Value: reqBody.name
            },
            {
                Name: 'family_name',
                Value: reqBody.lastname
            }
        ]
    }

    try{
        let signUp = await cognitoIdentityServiceProvider.signUp(params).promise()
    }catch(e){
        statusCode = 400
        console.error(e)
        responseMessage = { message: e.message }
    }

    return {
        statusCode: statusCode || 200,
        headers: {
          "Access-Control-Allow-Origin" : "*", // Required for CORS support to work
        },
        body: JSON.stringify(responseMessage || 'User registered. Must confirm mail'),
    };
}



exports.login = async (event, context,callback) => {
    let statusCode = null;
    let errorResponse = null
    const reqBody = JSON.parse(event.body)
    let loginDetail = null

    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: process.env.CLIENT_ID,
        AuthParameters:{
            USERNAME: reqBody.email,
            PASSWORD: reqBody.password,
        }
    }

    try{
        loginDetail = await cognitoIdentityServiceProvider.initiateAuth(params).promise()
    }catch(e){
        statusCode = 400
        errorResponse = {msg: e.message}
    }

    return {
        statusCode: statusCode || 200,
        headers: {
          "Access-Control-Allow-Origin" : "*", // Required for CORS support to work
        },
        body: JSON.stringify( errorResponse || loginDetail ),
    };
}

exports.recover = async (event, context,callback) => {
    let statusCode = null;
    let errorResponse = null
    let response = null
    
    const reqBody = JSON.parse(event.body)
    
    const params = {
        ClientId: process.env.CLIENT_ID,
        Username: reqBody.email,
    }

    try{
        response = await cognitoIdentityServiceProvider.forgotPassword(params).promise()
    }catch(e){
        statusCode = 400
        console.error("Error ", e)
        errorResponse = {msg: e.message}
    }

    return {
        statusCode: statusCode || 200,
        headers: {
          "Access-Control-Allow-Origin" : "*", // Required for CORS support to work
        },
        body: JSON.stringify( errorResponse || 'An email was sent in order to restart password.' ),
    };
}

exports.confirmRecover = async (event, context,callback) => {
    let statusCode = null;
    let errorResponse = null
    let response = null
    
    const reqBody = JSON.parse(event.body)
    
    const params = {
        ClientId: process.env.CLIENT_ID,
        ConfirmationCode: reqBody.confirmationCode,
        Password: reqBody.newPassword,
        Username: reqBody.email,
    }

    try{
        response = await cognitoIdentityServiceProvider.confirmForgotPassword(params).promise()
    }catch(e){
        statusCode = 400
        console.error("Error ", e)
        errorResponse = {msg: e.message}
    }

    return {
        statusCode: statusCode || 200,
        headers: {
          "Access-Control-Allow-Origin" : "*", // Required for CORS support to work
        },
        body: JSON.stringify( errorResponse || 'New password confirmated.' ),
    };
}