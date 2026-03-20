import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas";
import { WeightDistribution } from "./weight-dist";
import { Mutex } from "async-mutex";

export async function querySources(
  endpoint: string, 
  weightSourceIterator: QuerySourceIterator,
  dist: WeightDistribution,
  mutex: Mutex
) {
  const engine = new QueryEngine();

  const bindingsStream = await engine.queryBindings(Schemas.HCP_QUERY, {
    sources: [
      {
        value: endpoint,
        type: "graphql",
        context: {
          schema: Schemas.HCP_SLICE_SCHEMA,
          context: Schemas.HCP_SLICE_CONTEXT
        }
      }
    ]
  });

  bindingsStream.on('data', (b) => {
    if (b.has('pod') && b.has('id')) {
      const weightSource = {
        value: b.get('pod').value + Schemas.WEIGHT_SLICE,
        type: "graphql",
        context: {
          schema: Schemas.WEIGHT_SLICE_SCHEMA,
          context: Schemas.WEIGHT_SLICE_CONTEXT
        }
      }

      if (isAddition(b)) {
        weightSourceIterator.addSource(weightSource);
      } else {
        weightSourceIterator.removeSource(weightSource);
        mutex.runExclusive(() => dist.removePatient(b.get('id').value));
      }
    }
  });
}

export async function queryWeights(sourceIterater: QuerySourceIterator, dist: WeightDistribution, mutex: Mutex) {
  const engine = new QueryEngine();

  const bindingsStream = await engine.queryBindings(Schemas.WEIGHT_QUERY, {
    sources: [sourceIterater as any]
  });

  bindingsStream.on('data', (b) => {
    if (isAddition(b)) {
      if (b.has('value') && b.has('timestamp') && b.has('patient')) {
        const value = parseFloat(b.get('value').value);
        const timestamp = new Date(b.get('timestamp').value);
        const patientID = b.get('patient').value;

        mutex.runExclusive(() => dist.addWeightObservation(patientID, value, timestamp));
      }
    }
  });
}