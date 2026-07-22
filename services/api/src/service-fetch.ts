import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";

/**
 * Internal AI generation can exceed the five-minute header timeout embedded in
 * Node's fetch implementation. Use the core HTTP clients so the explicit
 * AbortSignal supplied by the adapter remains the only request deadline.
 */
export const longRunningServiceFetch: typeof fetch = async (input, init) => {
  const endpoint = serviceEndpoint(input);
  const transport = endpoint.protocol === "http:"
    ? httpRequest
    : endpoint.protocol === "https:"
      ? httpsRequest
      : null;
  if (!transport) throw new TypeError("AI service URL must use HTTP or HTTPS");

  const body = requestBody(init?.body);
  const headers = requestHeaders(init?.headers, body);

  return await new Promise<Response>((resolve, reject) => {
    const request = transport(endpoint, {
      method: init?.method ?? "GET",
      headers,
      signal: init?.signal ?? undefined,
    }, (incoming) => {
      const status = incoming.statusCode ?? 502;
      const responseHeaders = new Headers();
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        const name = incoming.rawHeaders[index];
        const value = incoming.rawHeaders[index + 1];
        if (name && value !== undefined) responseHeaders.append(name, value);
      }
      try {
        resolve(new Response(
          Readable.toWeb(incoming) as unknown as BodyInit,
          { status, statusText: incoming.statusMessage, headers: responseHeaders },
        ));
      } catch (error) {
        incoming.destroy();
        reject(error);
      }
    });
    request.once("error", reject);
    request.end(body);
  });
};

function serviceEndpoint(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof Request) {
    throw new TypeError("AI service Request objects are not supported");
  }
  return new URL(input);
}

function requestBody(body: BodyInit | null | undefined): Buffer | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body !== "string") {
    throw new TypeError("AI service request bodies must be JSON strings");
  }
  return Buffer.from(body, "utf8");
}

function requestHeaders(source: HeadersInit | undefined, body: Buffer | undefined): Record<string, string> {
  const headers = new Headers(source);
  if (body && !headers.has("content-length")) {
    headers.set("content-length", String(body.byteLength));
  }
  const result: Record<string, string> = {};
  headers.forEach((value, name) => {
    result[name] = value;
  });
  return result;
}
