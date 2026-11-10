import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  expect,
  setSystemTime,
  test,
} from "bun:test"
import { object, string } from "valibot"
import { createClient } from "../src/client.js"
import { issuer } from "../src/issuer.js"
import { Provider } from "../src/provider/provider.js"
import { DynamoStorage } from "../src/storage/dynamo.js"
import { Storage } from "../src/storage/storage.js"
import { createSubjects } from "../src/subject.js"

const AWS_ENV = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]
const savedEnv = Object.fromEntries(AWS_ENV.map((k) => [k, process.env[k]]))

// Minimal in-memory DynamoDB endpoint supporting the actions DynamoStorage uses.
const items = new Map<string, any>()
const id = (key: any) => `${key.pk.S}|${key.sk.S}`
let server: ReturnType<typeof Bun.serve>

beforeAll(() => {
  process.env.AWS_ACCESS_KEY_ID = "test"
  process.env.AWS_SECRET_ACCESS_KEY = "test"
  process.env.AWS_REGION = "us-east-1"
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const action = req.headers.get("X-Amz-Target")!.split(".")[1]
      const body = (await req.json()) as any
      switch (action) {
        case "PutItem":
          items.set(id(body.Item), body.Item)
          return Response.json({})
        case "GetItem":
          return Response.json({ Item: items.get(id(body.Key)) })
        case "DeleteItem":
          items.delete(id(body.Key))
          return Response.json({})
        case "Query": {
          const pk = body.ExpressionAttributeValues[":pk"].S
          const sk = body.ExpressionAttributeValues[":sk"]?.S ?? ""
          return Response.json({
            Items: [...items.values()].filter(
              (item) => item.pk.S === pk && item.sk.S.startsWith(sk),
            ),
          })
        }
      }
      return new Response("unsupported", { status: 400 })
    },
  })
})

afterAll(() => {
  server.stop()
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
})

beforeEach(() => {
  items.clear()
  setSystemTime(new Date("1/1/2024"))
})

afterEach(() => {
  setSystemTime()
})

const storage = () =>
  DynamoStorage({
    table: "test",
    endpoint: `http://localhost:${server.port}`,
  })

test("scan returns keys that can be passed to remove", async () => {
  const adapter = storage()
  await Storage.set(adapter, ["oauth:refresh", "user:1", "token-a"], {})
  await Storage.set(adapter, ["oauth:refresh", "user:1", "token-b"], {})
  await Storage.set(adapter, ["oauth:refresh", "user:2", "token-c"], {})

  const keys: string[][] = []
  for await (const [key] of Storage.scan(adapter, ["oauth:refresh", "user:1"]))
    keys.push(key)
  expect(keys.sort()).toEqual([
    ["oauth:refresh", "user:1", "token-a"],
    ["oauth:refresh", "user:1", "token-b"],
  ])

  for (const key of keys) await Storage.remove(adapter, key)

  expect(
    await Storage.get(adapter, ["oauth:refresh", "user:1", "token-a"]),
  ).toBeUndefined()
  expect(
    await Storage.get(adapter, ["oauth:refresh", "user:1", "token-b"]),
  ).toBeUndefined()
  expect(
    await Storage.get(adapter, ["oauth:refresh", "user:2", "token-c"]),
  ).toEqual({})
})

test("refresh token reuse detection revokes the rotated token", async () => {
  const subjects = createSubjects({ user: object({ userID: string() }) })
  const auth = issuer({
    storage: storage(),
    subjects,
    allow: async () => true,
    ttl: { access: 60, refresh: 6000, reuse: 60, retention: 6000 },
    providers: {
      dummy: {
        type: "dummy",
        init(route, ctx) {
          route.get("/authorize", (c) => ctx.success(c, {}))
        },
      } satisfies Provider<{}>,
    },
    success: async (ctx) => ctx.subject("user", { userID: "123" }),
  })
  const client = createClient({
    issuer: "https://auth.example.com",
    clientID: "123",
    fetch: (a, b) => Promise.resolve(auth.request(a, b)),
  })

  const { challenge, url } = await client.authorize(
    "https://client.example.com/callback",
    "code",
    { pkce: true },
  )
  let response = await auth.request(url)
  response = await auth.request(response.headers.get("location")!, {
    headers: { cookie: response.headers.get("set-cookie")! },
  })
  const code = new URL(response.headers.get("location")!).searchParams.get(
    "code",
  )
  const exchanged = await client.exchange(
    code!,
    "https://client.example.com/callback",
    challenge.verifier,
  )
  if (exchanged.err) throw exchanged.err

  const refresh = (refresh_token: string) =>
    auth.request("https://auth.example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token,
      }).toString(),
    })

  response = await refresh(exchanged.tokens.refresh)
  expect(response.status).toBe(200)
  const rotated = (await response.json()).refresh_token

  // replay the original token after the reuse interval
  setSystemTime(Date.now() + 1000 * 61)
  response = await refresh(exchanged.tokens.refresh)
  expect(response.status).toBe(400)

  // the token it was rotated into must now be revoked too
  response = await refresh(rotated)
  expect(response.status).toBe(400)
})
