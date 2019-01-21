const { GraphQLClient } = require("graphql-request");
const { promisify } = require("util");
const { normalizeEmail, isEmail } = require("validator");
const jwt = require("jsonwebtoken");
const express = require("express");
const { readFileSync } = require("fs");
const expressGraphql = require("express-graphql");
const { makeExecutableSchema } = require("graphql-tools");
const axios = require("axios");

let accessToken = "updog";

const sign = promisify(jwt.sign);

const {
  HASURA_GRAPHQL_ENDPOINT,
  HASURA_GRAPHQL_ACCESS_KEY,
  JWT_SECRET,
  PORT,
  SPOTIFY_CLIENT_ID,
  SPOTIFY_CLIENT_SECRET
} = process.env;

const typeDefs = readFileSync("./schema.graphql", "utf8");

const authHeader =
  "Basic " +
  Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString(
    "base64"
  );

const refreshToken = () =>
  axios
    .post("https://accounts.spotify.com/api/token", null, {
      headers: {
        Authorization: authHeader
      },
      params: { grant_type: "client_credentials" }
    })
    .then(({ data }) => (accessToken = data.access_token));

const search = (query, i = 0) =>
  axios
    .get(`https://api.spotify.com/v1/search?q=${query}&type=track`, {
      headers: {
        Authorization: "Bearer " + accessToken
      }
    })
    .then(({ data }) =>
      data.tracks.items.map(song => ({
        name: song.name,
        id: song.id,
        imageUrl: song.album.images[2].url,
        artistName: song.artists[0].name
      }))
    )
    .catch(async err => {
      if (err.response.status === 401) {
        await refreshToken();
        return i >= 5 ? [] : search(query, i + 1);
      } else {
        console.log(err.response.status, err.response.statusText);
        return [];
      }
    });

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
