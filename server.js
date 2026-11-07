import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, QueryCommand, DeleteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const requiredEnv = ['AWS_REGION', 'TABLE_NAME', 'COGNITO_CLIENT_ID'];
for (const v of requiredEnv) {
  if (!process.env[v]) {
    console.error('Missing environment variable: ' + v);
    process.exit(1);
  }
}
const REGION = process.env.AWS_REGION;
const TABLE_NAME = process.env.TABLE_NAME;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;

const ddbClient = new DynamoDBClient({ region: REGION });
const db = DynamoDBDocumentClient.from(ddbClient);
const cognito = new CognitoIdentityProviderClient({ region: REGION });

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const pairs = header.split(';');
  const cookies = {};
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      cookies[key] = val;
    }
  }
  return cookies;
}

async function requireUser(req, res, next) {
  try {
    const cookies = parseCookies(req);
    const token = cookies['at'];
    if (!token) {
      res.status(401).json({ error: 'Unauthenticated' });
      return;
    }
    const cmd = new GetUserCommand({ AccessToken: token });
    const data = await cognito.send(cmd);
    const attrs = {};
    for (const a of data.UserAttributes) {
      attrs[a.Name] = a.Value;
    }
    if (!attrs.sub || !attrs.email) {
      throw new Error('Missing attributes');
    }
    req.user = { sub: attrs.sub, email: attrs.email };
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/health', (req, res) => {
  res.type('text').send('ok');
});

/* Auth routes */
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cmd = new SignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: 'email', Value: email }]
    });
    await cognito.send(cmd);
    res.json({ message: 'Signup successful, check email for code' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/auth/confirm', async (req, res) => {
  try {
    const { email, code } = req.body;
    const cmd = new ConfirmSignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    });
    await cognito.send(cmd);
    res.json({ message: 'Confirmation successful' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cmd = new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password }
    });
    const result = await cognito.send(cmd);
    if (!result.AuthenticationResult) {
      res.status(400).json({ error: 'Authentication failed' });
      return;
    }
    const token = result.AuthenticationResult.AccessToken;
    res.setHeader('Set-Cookie', 'at=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=3300');
    res.json({ message: 'Logged in' });
  } catch (err) {
    if (err.name === 'UserNotConfirmedException') {
      res.status(403).json({ code: 'NOT_CONFIRMED' });
    } else {
      res.status(400).json({ error: err.message });
    }
  }
});

app.post('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'at=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});

app.get('/auth/me', async (req, res) => {
  try {
    const cookies = parseCookies(req);
    const token = cookies['at'];
    if (!token) {
      res.status(401).json({ error: 'Unauthenticated' });
      return;
    }
    const cmd = new GetUserCommand({ AccessToken: token });
    const data = await cognito.send(cmd);
    const attrs = {};
    for (const a of data.UserAttributes) {
      attrs[a.Name] = a.Value;
    }
    if (!attrs.email) {
      throw new Error('Email not found');
    }
    res.json({ email: attrs.email });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

/* Todo routes - protected */
app.use(requireUser);

app.get('/todos', async (req, res) => {
  try {
    const pk = 'USER#' + req.user.sub;
    const cmd = new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': pk },
      ScanIndexForward: false
    });
    const data = await db.send(cmd);
    const items = data.Items.map(i => ({
      id: i.sk.split('#')[1],
      content: i.content,
      completed: i.completed,
      createdAt: i.createdAt
    }));
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/todos', async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || typeof content !== 'string') {
      res.status(400).json({ error: 'Content required' });
      return;
    }
    const id = randomUUID();
    const now = new Date().toISOString();
    const item = {
      pk: 'USER#' + req.user.sub,
      sk: 'TODO#' + id,
      content: content,
      completed: false,
      createdAt: now
    };
    const cmd = new PutCommand({ TableName: TABLE_NAME, Item: item });
    await db.send(cmd);
    res.status(201).json({ id: id, content: content, completed: false, createdAt: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/todos/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const { content, completed } = req.body;
    const pk = 'USER#' + req.user.sub;
    const sk = 'TODO#' + id;
    const updateExp = [];
    const exprVals = {};
    if (content !== undefined) {
      updateExp.push('content = :c');
      exprVals[':c'] = content;
    }
    if (completed !== undefined) {
      updateExp.push('completed = :comp');
      exprVals[':comp'] = completed;
    }
    if (updateExp.length === 0) {
      res.status(400).json({ error: 'Nothing to update' });
      return;
    }
    const cmd = new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { pk: pk, sk: sk },
      UpdateExpression: 'SET ' + updateExp.join(', '),
      ExpressionAttributeValues: exprVals,
      ReturnValues: 'ALL_NEW'
    });
    const result = await db.send(cmd);
    const item = result.Attributes;
    res.json({
      id: id,
      content: item.content,
      completed: item.completed,
      createdAt: item.createdAt
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/todos/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const pk = 'USER#' + req.user.sub;
    const sk = 'TODO#' + id;
    const cmd = new DeleteCommand({ TableName: TABLE_NAME, Key: { pk: pk, sk: sk } });
    await db.send(cmd);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, '0.0.0.0', () => {
  console.log('Server listening on port 3000');
});
