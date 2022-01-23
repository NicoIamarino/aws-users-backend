module.exports.userDetail = async (event, context, callback) => {
    return {
        statusCode: 200,
        headers: {
          "Access-Control-Allow-Origin" : "*", // Required for CORS support to work
        },
        body: JSON.stringify( event.requestContext.authorizer),
    };
}
