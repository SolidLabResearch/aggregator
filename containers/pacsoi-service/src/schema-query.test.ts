import assert from "node:assert/strict";
import test from "node:test";
import { QueryMapper } from "@comunica-graphql/sparql2graphql-converter";
import { translate } from "sparqlalgebrajs";
import * as Schemas from "./schemas.js";

const queries = [
  ["patient", Schemas.PATIENT_SLICE_SCHEMA, Schemas.PATIENT_SLICE_CONTEXT, Schemas.PATIENT_QUERY],
  ["procedure", Schemas.BAR_PROCEDURE_SLICE_SCHEMA, Schemas.BAR_PROCEDURE_SLICE_CONTEXT, Schemas.PROCEDURE_QUERY],
  ["weight", Schemas.WEIGHT_SLICE_SCHEMA, Schemas.WEIGHT_SLICE_CONTEXT, Schemas.WEIGHT_QUERY],
  ["preop questionnaire", Schemas.QUESTIONNAIRE_PREOP_SLICE_SCHEMA, Schemas.QUESTIONNAIRE_SLICE_CONTEXT, Schemas.QUESTIONNAIRE_QUERY],
  ["6w questionnaire", Schemas.QUESTIONNAIRE_POSTOP6W_SLICE_SCHEMA, Schemas.QUESTIONNAIRE_SLICE_CONTEXT, Schemas.QUESTIONNAIRE_QUERY],
  ["3m questionnaire", Schemas.QUESTIONNAIRE_POSTOP3M_SLICE_SCHEMA, Schemas.QUESTIONNAIRE_SLICE_CONTEXT, Schemas.QUESTIONNAIRE_QUERY],
  ["6m questionnaire", Schemas.QUESTIONNAIRE_POSTOP6M_SLICE_SCHEMA, Schemas.QUESTIONNAIRE_SLICE_CONTEXT, Schemas.QUESTIONNAIRE_QUERY],
  ["1y questionnaire", Schemas.QUESTIONNAIRE_POSTOP1Y_SLICE_SCHEMA, Schemas.QUESTIONNAIRE_SLICE_CONTEXT, Schemas.QUESTIONNAIRE_QUERY],
] as const;

for (const [name, schema, context, query] of queries) {
  test(`${name} query supports an incremental addition subscription`, () => {
    const mapper = new QueryMapper(schema, context);
    const subscriptions = mapper.subscribeOperation(translate(query), "addition");
    assert.ok(subscriptions.length > 0);
  });
}
