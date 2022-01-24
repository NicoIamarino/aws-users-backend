const childProcess = require('child_process')

const executeCmd = (cmd,directory) => childProcess.execSync(cmd, {cwd: directory}).toString().trim()

console.log('Creating Cognito UserPool')
console.log(executeCmd('serverless deploy', './infra/cognito/userpool'))

console.log('Creating Cognito UserPoolClient and Domain')
console.log(executeCmd('serverless deploy', './infra/cognito/userpoolClient'))

console.log('Creating public endpoints - (Register/Login/Password Recover)')
console.log(executeCmd('serverless deploy', './services/users/public'))

console.log('Installing private endpoint dependencies')
console.log(executeCmd('npm install', './services/users/private'))

console.log('Creating private endpoints - (Current user details)')
console.log(executeCmd('serverless deploy', './services/users/private'))