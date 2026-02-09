import asyncio
import random
import uuid
from datetime import datetime, timedelta
from fastapi import FastAPI
from fastapi.responses import Response
import heapq

app = FastAPI()

# ============================================================
# Heap-based Quantile Tracker
# ============================================================

class QuantileTracker:
    """Tracks mean, 25th percentile, 75th percentile, and count incrementally."""
    def __init__(self):
        self.maxheap_75 = []  # max-heap for smallest 75% (-values)
        self.minheap_75 = []  # min-heap for largest 25%
        self.maxheap_25 = []  # max-heap for smallest 25% (-values)
        self.minheap_25 = []  # min-heap for largest 75%
        self.count = 0
        self.sum = 0.0

    def add(self, x: float):
        self.count += 1
        self.sum += x

        # --- 75th percentile ---
        if not self.maxheap_75 or x <= -self.maxheap_75[0]:
            heapq.heappush(self.maxheap_75, -x)
        else:
            heapq.heappush(self.minheap_75, x)

        # balance heaps
        target_maxheap_size = self.count * 3 // 4
        while len(self.maxheap_75) > target_maxheap_size:
            heapq.heappush(self.minheap_75, -heapq.heappop(self.maxheap_75))
        while len(self.maxheap_75) < target_maxheap_size:
            if self.minheap_75:
                heapq.heappush(self.maxheap_75, -heapq.heappop(self.minheap_75))
            else:
                break

        # --- 25th percentile ---
        if not self.minheap_25 or x >= self.minheap_25[0]:
            heapq.heappush(self.minheap_25, x)
        else:
            heapq.heappush(self.maxheap_25, -x)

        # balance heaps
        target_maxheap_size = self.count // 4
        while len(self.maxheap_25) > target_maxheap_size:
            heapq.heappush(self.minheap_25, -heapq.heappop(self.maxheap_25))
        while len(self.maxheap_25) < target_maxheap_size:
            if self.minheap_25:
                heapq.heappush(self.maxheap_25, -heapq.heappop(self.minheap_25))
            else:
                break

    def mean(self):
        return self.sum / self.count if self.count > 0 else 0.0

    def q75(self):
        return -self.maxheap_75[0] if self.maxheap_75 else None

    def q25(self):
        return self.minheap_25[0] if self.minheap_25 else None

    def total_count(self):
        return self.count

# ============================================================
# In-memory State
# ============================================================

patients = {}
# patient_pod_iri -> {"procedure_ts": datetime}

# Monthly quantile tracker
global_monthly = {}
# month_index -> QuantileTracker

state_lock = asyncio.Lock()
patient_stream = asyncio.Queue()

# ============================================================
# Utils
# ============================================================

def months_since(procedure_ts: datetime, event_ts: datetime) -> int:
    return (event_ts.year - procedure_ts.year) * 12 + (event_ts.month - procedure_ts.month)

# ============================================================
# Mock: Patient Pod IRI Stream Producer
# ============================================================

async def mock_patient_stream():
    active = set()
    while True:
        await asyncio.sleep(random.randint(2, 4))
        if not active or random.random() > 0.2:
            iri = f"pod_{uuid.uuid4().hex[:6]}"
            active.add(iri)
            await patient_stream.put({"type": "add", "patient_pod_iri": iri})
        else:
            iri = random.choice(list(active))
            active.remove(iri)
            await patient_stream.put({"type": "delete", "patient_pod_iri": iri})

# ============================================================
# Mock Procedure Fetch
# ============================================================

async def fetch_procedure(patient_pod_iri: str):
    await asyncio.sleep(0.2)
    return {
        "patient_id": str(uuid.uuid4()),
        "procedure_ts": datetime.now() - timedelta(days=random.randint(30, 365))
    }

# ============================================================
# Weight Stream per Patient
# ============================================================

async def weight_stream(patient_pod_iri: str):
    while True:
        await asyncio.sleep(random.randint(1, 3))
        timestamp = datetime.now()

        async with state_lock:
            if patient_pod_iri not in patients:
                break
            patient = patients[patient_pod_iri]
            procedure_ts = patient["procedure_ts"]

        if timestamp < procedure_ts:
            continue

        month_index = months_since(procedure_ts, timestamp)
        weight = random.uniform(60, 120)

        async with state_lock:
            if month_index not in global_monthly:
                global_monthly[month_index] = QuantileTracker()
            global_monthly[month_index].add(weight)

# ============================================================
# Patient Stream Listener
# ============================================================

async def patient_listener():
    while True:
        event = await patient_stream.get()
        iri = event["patient_pod_iri"]

        if event["type"] == "add":
            async with state_lock:
                if iri in patients:
                    continue
            procedure = await fetch_procedure(iri)
            async with state_lock:
                patients[iri] = {"procedure_ts": procedure["procedure_ts"]}
            asyncio.create_task(weight_stream(iri))

        elif event["type"] == "delete":
            async with state_lock:
                patients.pop(iri, None)

# ============================================================
# CSV Report Endpoint (Plain Text)
# ============================================================

@app.get("/report")
async def report():
    lines = ["month,avg_weight,quantile_25,quantile_75,count"]

    async with state_lock:
        snapshot = {month: tracker for month, tracker in global_monthly.items()}

    for month, tracker in sorted(snapshot.items()):
        if tracker.total_count() > 0:
            lines.append(
                f"{month},{tracker.mean():.2f},{tracker.q25():.2f},{tracker.q75():.2f},{tracker.total_count()}"
            )

    csv_text = "\n".join(lines)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=report.csv"}
    )

# ============================================================
# Startup Tasks
# ============================================================

@app.on_event("startup")
async def startup():
    asyncio.create_task(mock_patient_stream())
    asyncio.create_task(patient_listener())

# ============================================================
# Local Run
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
