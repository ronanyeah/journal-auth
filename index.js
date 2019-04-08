const { GraphQLClient } = require("graphql-request");
const { promisify } = require("util");
const { normalizeEmail, isEmail } = require("validator");
const jwt = require("jsonwebtoken");
const express = require("express");
const { readFileSync } = require("fs");
const expressGraphql = require("express-graphql");
const { makeExecutableSchema } = require("graphql-tools");
const axios = require("axios");

const sign = promisify(jwt.sign);

const {
  HASURA_GRAPHQL_ENDPOINT,
  HASURA_GRAPHQL_ACCESS_KEY,
  JWT_SECRET,
  PORT
} = process.env;

const typeDefs = readFileSync("./schema.graphql", "utf8");

const search = query =>
  axios
    .get(
      `http://ws.audioscrobbler.com/2.0/?method=track.search&track=${query}&api_key=${"9da38c677347e0ff817f60685ae4b447"}&format=json`
    )
    .then(({ data }) =>
      data.results.trackmatches.track.map(song => ({
        name: song.name,
        id: "song.id",
        imageUrl: song.image[0]["#text"],
        artistName: song.artist
      }))
    );

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
        "x-hasura-allowed-roles": ["user", "anon"],
        "x-hasura-default-role": "user",
        "x-hasura-user-id": id.toString()
      }
    },
    JWT_SECRET
  );

const resolvers = {
  Query: {
    nonce: async (_, { email }) => {
      const {
        user: [u]
      } = await client.request(getNonce(normalizeEmail(email)));

      return u ? u.nonce : Error("invalid email or password");
    },
    spotify: async (_, { query }) => search(query)
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
};

const app = express();

app.use(
  "/graphql",
  expressGraphql({
    schema: makeExecutableSchema({
      typeDefs,
      resolvers
    })
  })
);

app.listen(PORT, () =>
  console.log(`GraphQL server is running on port ${PORT}!`)
);
