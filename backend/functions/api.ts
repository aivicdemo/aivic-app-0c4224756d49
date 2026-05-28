import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { getUserFromEvent, checkPermission, User } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface APIGatewayEvent {
  httpMethod: string;
  path: string;
  pathParameters?: { [key: string]: string };
  queryStringParameters?: { [key: string]: string };
  body?: string;
  requestContext: any;
}

interface APIResponse {
  statusCode: number;
  headers: { [key: string]: string };
  body: string;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
};

function createResponse(statusCode: number, body: any): APIResponse {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(body)
  };
}

function createErrorResponse(statusCode: number, message: string): APIResponse {
  return createResponse(statusCode, { error: message });
}

async function createAuditLog(user: User, action: string, target: string, details?: any): Promise<void> {
  const auditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    userId: user.id,
    action,
    target,
    details: details || {},
    timestamp: new Date().toISOString(),
    createdAt: new Date().toISOString()
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
}

function validateRequired(data: any, fields: string[]): string[] {
  const errors: string[] = [];
  for (const field of fields) {
    if (!data[field]) {
      errors.push(`${field} is required`);
    }
  }
  return errors;
}

function addTimestamps(item: any, isUpdate = false): any {
  const now = new Date().toISOString();
  if (!isUpdate) {
    item.createdAt = now;
  }
  item.updatedAt = now;
  return item;
}

async function handleGetResources(event: APIGatewayEvent, user: User): Promise<APIResponse> {
  try {
    checkPermission(user, 'resources:read');
    
    const result = await docClient.send(new ScanCommand({
      TableName: TABLE_NAME,
      FilterExpression: 'begins_with(pk, :pk)',
      ExpressionAttributeValues: {
        ':pk': 'USER#'
      }
    }));
    
    return createResponse(200, {
      items: result.Items || [],
      count: result.Count || 0
    });
  } catch (error: any) {
    if (error.message.includes('Insufficient permissions')) {
      return createErrorResponse(403, error.message);
    }
    return createErrorResponse(500, 'Internal server error');
  }
}

async function handleBulkImport(event: APIGatewayEvent, user: User, tableType: string): Promise<APIResponse> {
  try {
    checkPermission(user, 'bulk:import');
    
    if (!event.body) {
      return createErrorResponse(400, 'Request body is required');
    }
    
    const { items } = JSON.parse(event.body);
    if (!Array.isArray(items)) {
      return createErrorResponse(400, 'Items must be an array');
    }
    
    let imported = 0;
    let failed = 0;
    const errors: string[] = [];
    
    // Process in batches of 25 (DynamoDB BatchWrite limit)
    for (let i = 0; i < items.length; i += 25) {
      const batch = items.slice(i, i + 25);
      const writeRequests = batch.map(item => {
        const processedItem = {
          ...item,
          id: item.id || randomUUID(),
          pk: `${tableType.toUpperCase()}#${item.id || randomUUID()}`,
          sk: item.sk || 'METADATA',
          ...addTimestamps(item)
        };
        
        return {
          PutRequest: {
            Item: processedItem
          }
        };
      });
      
      try {
        await docClient.send(new BatchWriteCommand({
          RequestItems: {
            [TABLE_NAME]: writeRequests
          }
        }));
        imported += batch.length;
      } catch (error: any) {
        failed += batch.length;
        errors.push(`Batch ${Math.floor(i/25) + 1}: ${error.message}`);
      }
    }
    
    await createAuditLog(user, 'BULK_IMPORT', tableType, {
      imported,
      failed,
      totalItems: items.length
    });
    
    return createResponse(200, {
      imported,
      failed,
      errors
    });
  } catch (error: any) {
    if (error.message.includes('Insufficient permissions')) {
      return createErrorResponse(403, error.message);
    }
    return createErrorResponse(400, error.message);
  }
}

export const handler = async (event: APIGatewayEvent): Promise<APIResponse> => {
  if (event.httpMethod === 'OPTIONS') {
    return createResponse(200, {});
  }
  
  try {
    const user = getUserFromEvent(event);
    const path = event.path;
    const method = event.httpMethod;
    
    // Handle bulk import endpoints
    const bulkImportMatch = path.match(/^\/api\/(\w+)\/bulk$/);
    if (bulkImportMatch && method === 'POST') {
      const tableType = bulkImportMatch[1];
      return await handleBulkImport(event, user, tableType);
    }
    
    // Handle main endpoints
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event, user);
    }
    
    // Handle user management
    if (path.startsWith('/users')) {
      if (method === 'GET' && !event.pathParameters?.id) {
        checkPermission(user, 'users:read');
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk)',
          ExpressionAttributeValues: { ':pk': 'USER#' }
        }));
        return createResponse(200, { items: result.Items || [] });
      }
      
      if (method === 'GET' && event.pathParameters?.id) {
        checkPermission(user, 'users:read');
        const result = await docClient.send(new GetCommand({
          TableName: TABLE_NAME,
          Key: { pk: `USER#${event.pathParameters.id}`, sk: 'METADATA' }
        }));
        if (!result.Item) {
          return createErrorResponse(404, 'User not found');
        }
        return createResponse(200, result.Item);
      }
      
      if (method === 'POST') {
        checkPermission(user, 'users:write');
        const data = JSON.parse(event.body || '{}');
        const errors = validateRequired(data, ['loginId', 'passwordHash', 'userName', 'email', 'userType', 'activeFlag']);
        if (errors.length > 0) {
          return createErrorResponse(400, errors.join(', '));
        }
        
        const userId = randomUUID();
        const item = {
          pk: `USER#${userId}`,
          sk: 'METADATA',
          id: userId,
          ...data,
          ...addTimestamps(data),
          createdBy: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: item
        }));
        
        await createAuditLog(user, 'CREATE_USER', userId, data);
        return createResponse(201, item);
      }
      
      if (method === 'PUT' && event.pathParameters?.id) {
        checkPermission(user, 'users:write');
        const data = JSON.parse(event.body || '{}');
        const userId = event.pathParameters.id;
        
        const updateItem = {
          ...data,
          ...addTimestamps(data, true)
        };
        
        await docClient.send(new UpdateCommand({
          TableName: TABLE_NAME,
          Key: { pk: `USER#${userId}`, sk: 'METADATA' },
          UpdateExpression: 'SET #data = :data',
          ExpressionAttributeNames: { '#data': 'data' },
          ExpressionAttributeValues: { ':data': updateItem }
        }));
        
        await createAuditLog(user, 'UPDATE_USER', userId, data);
        return createResponse(200, { id: userId, ...updateItem });
      }
      
      if (method === 'DELETE' && event.pathParameters?.id) {
        checkPermission(user, 'users:delete');
        const userId = event.pathParameters.id;
        
        await docClient.send(new DeleteCommand({
          TableName: TABLE_NAME,
          Key: { pk: `USER#${userId}`, sk: 'METADATA' }
        }));
        
        await createAuditLog(user, 'DELETE_USER', userId);
        return createResponse(204, {});
      }
    }
    
    // Handle project management
    if (path.startsWith('/projects')) {
      if (method === 'GET' && !event.pathParameters?.id) {
        checkPermission(user, 'projects:read');
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk)',
          ExpressionAttributeValues: { ':pk': 'PROJECT#' }
        }));
        return createResponse(200, { items: result.Items || [] });
      }
      
      if (method === 'GET' && event.pathParameters?.id) {
        checkPermission(user, 'projects:read');
        const result = await docClient.send(new GetCommand({
          TableName: TABLE_NAME,
          Key: { pk: `PROJECT#${event.pathParameters.id}`, sk: 'METADATA' }
        }));
        if (!result.Item) {
          return createErrorResponse(404, 'Project not found');
        }
        return createResponse(200, result.Item);
      }
      
      if (method === 'POST') {
        checkPermission(user, 'projects:write');
        const data = JSON.parse(event.body || '{}');
        const errors = validateRequired(data, ['projectName', 'researchField', 'researchOverview', 'researchLeaderId', 'startDate', 'status', 'publicFlag', 'progressRate']);
        if (errors.length > 0) {
          return createErrorResponse(400, errors.join(', '));
        }
        
        const projectId = randomUUID();
        const item = {
          pk: `PROJECT#${projectId}`,
          sk: 'METADATA',
          id: projectId,
          ...data,
          ...addTimestamps(data),
          createdById: user.id,
          updatedById: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: item
        }));
        
        await createAuditLog(user, 'CREATE_PROJECT', projectId, data);
        return createResponse(201, item);
      }
    }
    
    // Handle sustainability indicators
    if (path.startsWith('/sustainability-indicators')) {
      if (method === 'GET' && !event.pathParameters?.id) {
        checkPermission(user, 'sustainability:read');
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk)',
          ExpressionAttributeValues: { ':pk': 'SUSTAINABILITY_INDICATOR#' }
        }));
        return createResponse(200, { items: result.Items || [] });
      }
      
      if (method === 'POST') {
        checkPermission(user, 'sustainability:write');
        const data = JSON.parse(event.body || '{}');
        const errors = validateRequired(data, ['projectId', 'evaluationStartDate', 'evaluationEndDate', 'environmentalImpactScore', 'socialContributionScore', 'economicEffectScore', 'overallEvaluationScore', 'evaluationRank', 'evaluationStatus', 'evaluatorId']);
        if (errors.length > 0) {
          return createErrorResponse(400, errors.join(', '));
        }
        
        const indicatorId = randomUUID();
        const item = {
          pk: `SUSTAINABILITY_INDICATOR#${indicatorId}`,
          sk: 'METADATA',
          id: indicatorId,
          ...data,
          ...addTimestamps(data),
          createdById: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: item
        }));
        
        await createAuditLog(user, 'CREATE_SUSTAINABILITY_INDICATOR', indicatorId, data);
        return createResponse(201, item);
      }
    }
    
    // Handle privacy risk items
    if (path.startsWith('/privacy-risk-items')) {
      if (method === 'GET' && !event.pathParameters?.id) {
        checkPermission(user, 'privacy:read');
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk)',
          ExpressionAttributeValues: { ':pk': 'PRIVACY_RISK_ITEM#' }
        }));
        return createResponse(200, { items: result.Items || [] });
      }
      
      if (method === 'POST') {
        checkPermission(user, 'privacy:write');
        const data = JSON.parse(event.body || '{}');
        const errors = validateRequired(data, ['riskItemName', 'riskClassification', 'riskLevel', 'riskContent', 'targetDataType', 'activeFlag', 'displayOrder']);
        if (errors.length > 0) {
          return createErrorResponse(400, errors.join(', '));
        }
        
        const riskItemId = randomUUID();
        const item = {
          pk: `PRIVACY_RISK_ITEM#${riskItemId}`,
          sk: 'METADATA',
          id: riskItemId,
          ...data,
          ...addTimestamps(data),
          createdById: user.id,
          updatedById: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: item
        }));
        
        await createAuditLog(user, 'CREATE_PRIVACY_RISK_ITEM', riskItemId, data);
        return createResponse(201, item);
      }
    }
    
    // Handle notifications
    if (path.startsWith('/notifications')) {
      if (method === 'GET' && !event.pathParameters?.id) {
        checkPermission(user, 'notifications:read');
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk) AND receiverUserId = :userId',
          ExpressionAttributeValues: {
            ':pk': 'NOTIFICATION#',
            ':userId': user.id
          }
        }));
        return createResponse(200, { items: result.Items || [] });
      }
      
      if (method === 'POST') {
        checkPermission(user, 'notifications:write');
        const data = JSON.parse(event.body || '{}');
        const errors = validateRequired(data, ['receiverUserId', 'notificationType', 'title', 'messageContent', 'priority', 'readFlag']);
        if (errors.length > 0) {
          return createErrorResponse(400, errors.join(', '));
        }
        
        const notificationId = randomUUID();
        const item = {
          pk: `NOTIFICATION#${notificationId}`,
          sk: 'METADATA',
          id: notificationId,
          ...data,
          ...addTimestamps(data),
          createdById: user.id
        };
        
        await docClient.send(new PutCommand({
          TableName: TABLE_NAME,
          Item: item
        }));
        
        await createAuditLog(user, 'CREATE_NOTIFICATION', notificationId, data);
        return createResponse(201, item);
      }
    }
    
    return createErrorResponse(404, 'Endpoint not found');
    
  } catch (error: any) {
    console.error('Handler error:', error);
    if (error.message.includes('No authorization claims')) {
      return createErrorResponse(401, 'Unauthorized');
    }
    if (error.message.includes('Insufficient permissions')) {
      return createErrorResponse(403, error.message);
    }
    return createErrorResponse(500, 'Internal server error');
  }
};