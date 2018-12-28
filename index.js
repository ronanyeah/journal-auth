const { GraphQLClient } = require("graphql-request");
const { promisify } = require("util");
const { normalizeEmail, isEmail } = require("validator");
const jwt = require("jsonwebtoken");
const { GraphQLServer } = require("graphql-yoga");
const { resolve } = require("path");

const sign = promisify(jwt.sign);

const {
  HASURA_GRAPHQL_ENDPOINT,
  HASURA_GRAPHQL_ACCESS_KEY,
  JWT_SECRET,
  PORT
} = process.env;

const client = new GraphQLClient(
  HASURA_GRAPHQL_ENDPOINT + "/v1alpha1/graphql",
  {
    headers: {
      "X-Hasura-Access-Key": HASURA_GRAPHQL_ACCESS_KEY
    }
  }
);

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

new GraphQLServer({
  port: PORT,
  typeDefs: resolve(__dirname, "./schema.graphql"),
  resolvers: {
    Query: {
      nonce: async (_, { email }) => {
        const {
          user: [u]
        } = await client.request(getNonce(normalizeEmail(email)));

        return u ? u.nonce : Error("invalid email or password");
      }
    },
    Mutation: {
      login: async (_, { email, password }) => {
        const {
          user: [u]
        } = await client.request(query(normalizeEmail(email), password));

        return u ? token(u.id) : Error("invalid email or password");
      },
      signup: async (_, { email, password, nonce }) => {
        if (!isEmail(email)) {
          return Error("not a valid email address");
        }
        const data = await client
          .request(insert(normalizeEmail(email), password, nonce))
          .catch(() => null);

        if (!data) {
          return Error("this user already exists");
        }

        const {
          insert_user: {
            returning: [{ id }]
          }
        } = data;

        return token(id);
      }
    }
  }
}).start(({ port }) =>
  console.log(`GraphQL server is running on port ${port}!`)
);
