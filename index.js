const { GraphQLClient } = require("graphql-request");
const { promisify } = require("util");
const { normalizeEmail, isEmail } = require("validator");
const jwt = require("jsonwebtoken");
const restify = require("restify");
const corsMiddleware = require("restify-cors-middleware");

const sign = promisify(jwt.sign);

const { HASURA_URL, ACCESS_KEY, JWT_SECRET, PORT } = process.env;

const client = new GraphQLClient(HASURA_URL, {
  headers: {
    "X-Hasura-Access-Key": ACCESS_KEY
  }
});

const query = (email, pw) => `\
{
  user(where: {email: {_eq: "${email}"}, password: {_eq: "${pw}"}}) {
    id
  }
}
`;

const insert = (email, pw, nonce) => `\
mutation {
  insert_user(objects:[{email:"${email}", password: "${pw}", nonce: "${nonce}"}]) {
    returning {
      id
    }
  }
}
`;

const getNonce = email => `\
{
  user(where: {email: {_eq: "${email}"}}) {
    nonce
  }
}
`;

const token = id =>
  sign(
    {
      sub: id.toString(),
      iat: Date.now() / 1000,
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["editor", "user", "mod"],
        "x-hasura-default-role": "user",
        "x-hasura-user-id": id.toString()
      }
    },
    JWT_SECRET
  );

const server = restify.createServer();

const cors = corsMiddleware({
  preflightMaxAge: 5,
  origins: ["*"],
  allowHeaders: [],
  exposeHeaders: []
});

server.pre(cors.preflight);

server.use(cors.actual);

server.use(restify.plugins.bodyParser());

server.post("/auth/signup", async (request, response) => {
  const { email, nonce, password } = request.body;
  if (!isEmail(email)) {
    return response.send(400, {
      errors: ["not a valid email address"]
    });
  }
  const data = await client
    .request(insert(normalizeEmail(email), password, nonce))
    .catch(() => null);

  if (!data) {
    return response.send(400, {
      errors: ["this user already exists"]
    });
  }

  const {
    insert_user: {
      returning: [{ id }]
    }
  } = data;

  return response.send({ id, token: await token(id) });
});

server.post("/auth/login", async (request, response) => {
  const { email, password } = request.body;
  const {
    user: [u]
  } = await client.request(query(normalizeEmail(email), password));
  return u
    ? response.send({ token: await token(u.id), id: u.id })
    : response.send(404, {
        errors: ["invalid email or password"]
      });
});

server.post("/auth/nonce", async (request, response) => {
  const { email } = request.body;
  const {
    user: [u]
  } = await client.request(getNonce(normalizeEmail(email)));
  return u
    ? response.send({ nonce: u.nonce })
    : response.send(404, {
        errors: ["invalid email or password"]
      });
});

server.listen(PORT, () => console.log(`server listening on port: ${PORT}`));
