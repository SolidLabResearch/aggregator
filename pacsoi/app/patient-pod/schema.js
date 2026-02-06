const { makeExecutableSchema } = require("@graphql-tools/schema");
const GraphQLJSON = require("graphql-type-json");
const { PubSub } = require("graphql-subscriptions");

const pubsub = new PubSub();

const typeDefs = `#graphql
  scalar JSON

  type ex_Observation {
    id: ID!
    ex_value: Int!
    ex_unit: String!
    ex_timestamp: JSON!
  }

  type Subscription {
    observationAdded: ex_Observation!
  }

  type Query {
    _empty: String
  }
`;

const resolvers = {
  JSON: GraphQLJSON,

  Subscription: {
    observationAdded: {
      subscribe: () => pubsub.asyncIterator(["OBSERVATION_ADDED"]),
    },
  },
};

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Mock generator
function createObservation() {
  return {
    id: `http://example.com/obs${Math.floor(Math.random() * 1000)}`,
    ex_value: Math.floor(Math.random() * 100),
    ex_unit: "kg",
    ex_timestamp: {
      _rawRDF: {
        "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
        "@value": new Date().toISOString(),
      },
    },
  };
}

function startMockStream() {
  setInterval(() => {
    pubsub.publish("OBSERVATION_ADDED", {
      observationAdded: createObservation(),
    });
  }, 2000);
}

module.exports = {
  schema,
  startMockStream,
};