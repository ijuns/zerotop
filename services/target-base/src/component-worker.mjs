import { pathToFileURL } from "node:url";
import { parentPort, workerData } from "node:worker_threads";

if (!parentPort) throw new Error("component worker requires a parent port");

try {
  const module = await import(pathToFileURL(workerData.handlerPath).href);
  if (typeof module.handle !== "function") throw new Error("signed component must export handle");
  const result = await module.handle(
    Object.freeze({ ...workerData.request }),
    Object.freeze({ componentId: workerData.componentId, operation: workerData.operation }),
  );
  parentPort.postMessage(result);
} catch {
  throw new Error("signed component handler failed");
}
