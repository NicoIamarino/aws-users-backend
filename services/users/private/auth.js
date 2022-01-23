"use strict";

const jsonwebtoken = require('jsonwebtoken');
const Axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const util = require('util');

module.exports.auth = async (event, context, callback) => {

    let error = null
    const pool = `https://cognito-idp.us-east-1.amazonaws.com/${process.env.USER_POOL_ID}`;

    let decodedToken = jsonwebtoken.decode(event.authorizationToken);
    
    const tokenSections = event.authorizationToken.split('.');

    try{
        //Step 1: Confirm the Structure of the JWT 
        if (tokenSections.length < 2) { throw new Error('requested token is invalid'); }

        // //Step 2: Validate the JWT Signature 
        const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
        const header = JSON.parse(headerJSON);
        const keys = await getPublicKeys(decodedToken.iss);
        const key = keys[header.kid];
        if (key === undefined) {
            throw new Error('claim made for unknown kid');
        }
    
        const claim = await verifyPromised(event.authorizationToken, key.pem);
    
        //Step 3: Verify the Claims 
        const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
        if (currentSeconds > decodedToken.exp || currentSeconds < decodedToken.auth_time) {
            throw new Error('claim is expired or invalid');
        }
        if (! (pool == decodedToken.iss) ) {
            // if (claim.iss !== cognitoIssuer) {
            throw new Error('claim issuer is invalid');
        }
        if (decodedToken.token_use !== 'id') {
            throw new Error('claim use is not id');
        }

        console.log(`claim confirmed for ${decodedToken.email}`);
        callback(null, buildAllowAllPolicy(event, decodedToken.sub, decodedToken));

    }catch(e){
        console.error(e)
        callback("Unauthorized");
    }
};

const verifyPromised = util.promisify(jsonwebtoken.verify.bind(jsonwebtoken));

const getPublicKeys = async (issuerUrl) => {
    const url = `${issuerUrl}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get(url);
    let cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
        const pem = jwkToPem(current);
        agg[current.kid] = { instance: current, pem };
        return agg;
    }, {});
    return cacheKeys;
};

function buildAllowAllPolicy(event, principalId, decodedToken) {
    var apiOptions = {}
    var tmp = event.methodArn.split(':')
    var apiGatewayArnTmp = tmp[5].split('/')
    var awsAccountId = tmp[4]
    var awsRegion = tmp[3]
    var restApiId = apiGatewayArnTmp[0]
    var stage = apiGatewayArnTmp[1]
    var apiArn = 'arn:aws:execute-api:' + awsRegion + ':' + awsAccountId + ':' +
        restApiId + '/' + stage + '/*/*'
    const policy = {
        principalId: principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: 'Allow',
                    Resource: [apiArn]
                }
            ]
        }
    };

    policy.context = Object.assign({}, getMainAttributes(decodedToken), getCustomAttributes(decodedToken))

    return policy;
}

const getMainAttributes = (token) => {
    return {
        name: token.name,
        lastname: token.family_name,
        email: token.email
    }
}

const getCustomAttributes = ( token ) => {
    let customAttrs = {}
    const customArr = Object.entries(token).filter( entry => entry[0].startsWith('custom:') )
    customArr.forEach( entry => customAttrs[entry[0]] = entry[1])
    return customAttrs;
}