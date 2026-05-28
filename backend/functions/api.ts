import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { hasPermission, extractUserRole, Role } from './rbac';
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
  headers?: { [key: string]: string };
}

interface APIGatewayResponse {
  statusCode: number;
  headers: { [key: string]: string };
  body: string;
}

const TABLE_CONFIGS = {
  '0': { name: 'ログインユーザー', pk: 'USER' },
  '1': { name: '研究プロジェクト', pk: 'PROJECT' },
  '2': { name: '研究データ', pk: 'RESEARCH_DATA' },
  '3': { name: '操作履歴', pk: 'OPERATION_LOG' },
  '4': { name: '持続可能性指標', pk: 'SUSTAINABILITY_INDICATOR' },
  '5': { name: '持続可能性評価データ', pk: 'SUSTAINABILITY_EVALUATION' },
  '6': { name: 'バーチャル世界サービス', pk: 'VIRTUAL_SERVICE' },
  '7': { name: 'プライバシーリスク項目', pk: 'PRIVACY_RISK_ITEM' },
  '8': { name: 'プライバシーリスク評価', pk: 'PRIVACY_RISK_EVALUATION' },
  '9': { name: '分析結果', pk: 'ANALYSIS_RESULT' },
  '10': { name: '通知', pk: 'NOTIFICATION' }
};

function createResponse(statusCode: number, body: any): APIGatewayResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    },
    body: JSON.stringify(body)
  };
}

async function writeAuditLog(action: string, details: any, userId?: string): Promise<void> {
  try {
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        pk: 'AUDIT',
        sk: `${Date.now()}_${randomUUID()}`,
        action,
        details,
        userId: userId || 'system',
        timestamp: new Date().toISOString()
      }
    }));
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

function validateRequired(item: any, requiredFields: string[]): string[] {
  const errors: string[] = [];
  for (const field of requiredFields) {
    if (!item[field]) {
      errors.push(`${field} is required`);
    }
  }
  return errors;
}

function getRequiredFields(tableIndex: string): string[] {
  const fieldMap: { [key: string]: string[] } = {
    '0': ['ログインID', 'パスワードハッシュ', 'ユーザー名', 'メールアドレス', 'ユーザー種別'],
    '1': ['プロジェクト名', '研究分野', '研究概要', '研究責任者ID', '開始日', 'ステータス'],
    '2': ['研究プロジェクトID', 'データ名', 'データ種別', '分析状況', '作成者ID'],
    '3': ['ユーザーID', '操作種別', '画面名', '機能名', 'IPアドレス', '実行結果'],
    '4': ['プロジェクトID', '評価期間開始日', '評価期間終了日', '環境影響スコア', '社会貢献スコア', '経済効果スコア', '総合評価スコア', '評価ランク', '評価ステータス', '評価者ID'],
    '5': ['プロジェクトID', '指標ID', '評価期間開始日', '評価期間終了日', '評価値', '評価ステータス', '評価者ID'],
    '6': ['サービス名', '研究プロジェクトID', 'サービス種別', '利用可能ユーザー数', 'サービス状態', '開始日時'],
    '7': ['リスク項目名', 'リスク分類', 'リスクレベル', 'リスク内容', '対象データ種別', '表示順序'],
    '8': ['研究プロジェクトID', 'プライバシーリスク項目ID', 'リスクレベル', '対応状況', '評価者ID', '評価日', '承認状況'],
    '9': ['研究プロジェクトID', '分析タイトル', '分析種別', '分析内容', 'ステータス', '分析実行日'],
    '10': ['受信者ユーザーID', '通知タイプ', 'タイトル', 'メッセージ内容', '優先度']
  };
  return fieldMap[tableIndex] || [];
}

export const handler = async (event: APIGatewayEvent): Promise<APIGatewayResponse> => {
  try {
    if (event.httpMethod === 'OPTIONS') {
      return createResponse(200, {});
    }

    const userRole = extractUserRole(event);
    const path = event.path;
    const method = event.httpMethod;

    if (path === '/resources' && method === 'GET') {
      if (!hasPermission(userRole, 'resources', 'read')) {
        return createResponse(403, { error: 'Insufficient permissions' });
      }

      try {
        const resources = Object.entries(TABLE_CONFIGS).map(([index, config]) => ({
          index,
          name: config.name,
          pk: config.pk
        }));
        return createResponse(200, { resources });
      } catch (error) {
        console.error('Error fetching resources:', error);
        return createResponse(500, { error: 'Internal server error' });
      }
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      const tableIndex = bulkMatch[1];
      const tableConfig = TABLE_CONFIGS[tableIndex as keyof typeof TABLE_CONFIGS];
      
      if (!tableConfig) {
        return createResponse(404, { error: 'Table not found' });
      }

      if (!hasPermission(userRole, tableConfig.pk, 'bulk')) {
        return createResponse(403, { error: 'Insufficient permissions for bulk operations' });
      }

      try {
        const body = JSON.parse(event.body || '{}');
        const items = body.items || [];
        
        if (!Array.isArray(items)) {
          return createResponse(400, { error: 'Items must be an array' });
        }

        const requiredFields = getRequiredFields(tableIndex);
        let imported = 0;
        let failed = 0;
        const errors: string[] = [];
        const now = new Date().toISOString();

        for (let i = 0; i < items.length; i += 25) {
          const batch = items.slice(i, i + 25);
          const writeRequests = [];

          for (const item of batch) {
            const validationErrors = validateRequired(item, requiredFields);
            if (validationErrors.length > 0) {
              failed++;
              errors.push(`Item ${i + batch.indexOf(item)}: ${validationErrors.join(', ')}`);
              continue;
            }

            const processedItem = {
              ...item,
              pk: tableConfig.pk,
              sk: item.id || randomUUID(),
              id: item.id || randomUUID(),
              createdAt: now,
              updatedAt: now,
              作成日時: now,
              更新日時: now
            };

            writeRequests.push({
              PutRequest: {
                Item: processedItem
              }
            });
          }

          if (writeRequests.length > 0) {
            try {
              await docClient.send(new BatchWriteCommand({
                RequestItems: {
                  [TABLE_NAME]: writeRequests
                }
              }));
              imported += writeRequests.length;
            } catch (error) {
              failed += writeRequests.length;
              errors.push(`Batch write failed: ${error}`);
            }
          }
        }

        await writeAuditLog('BULK_IMPORT', {
          tableIndex,
          tableName: tableConfig.name,
          imported,
          failed,
          totalItems: items.length
        });

        return createResponse(200, { imported, failed, errors });
      } catch (error) {
        console.error('Bulk import error:', error);
        return createResponse(500, { error: 'Internal server error' });
      }
    }

    const apiMatch = path.match(/^\/api\/(\d+)(?:\/(\w+))?$/);
    if (apiMatch) {
      const tableIndex = apiMatch[1];
      const itemId = apiMatch[2];
      const tableConfig = TABLE_CONFIGS[tableIndex as keyof typeof TABLE_CONFIGS];
      
      if (!tableConfig) {
        return createResponse(404, { error: 'Table not found' });
      }

      switch (method) {
        case 'GET':
          if (!hasPermission(userRole, tableConfig.pk, 'read')) {
            return createResponse(403, { error: 'Insufficient permissions' });
          }

          try {
            if (itemId) {
              const result = await docClient.send(new GetCommand({
                TableName: TABLE_NAME,
                Key: { pk: tableConfig.pk, sk: itemId }
              }));
              
              if (!result.Item) {
                return createResponse(404, { error: 'Item not found' });
              }
              
              return createResponse(200, result.Item);
            } else {
              const result = await docClient.send(new ScanCommand({
                TableName: TABLE_NAME,
                FilterExpression: 'pk = :pk',
                ExpressionAttributeValues: { ':pk': tableConfig.pk }
              }));
              
              return createResponse(200, { items: result.Items || [] });
            }
          } catch (error) {
            console.error('Get operation error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }

        case 'POST':
          if (!hasPermission(userRole, tableConfig.pk, 'create')) {
            return createResponse(403, { error: 'Insufficient permissions' });
          }

          try {
            const body = JSON.parse(event.body || '{}');
            const requiredFields = getRequiredFields(tableIndex);
            const validationErrors = validateRequired(body, requiredFields);
            
            if (validationErrors.length > 0) {
              return createResponse(400, { error: 'Validation failed', details: validationErrors });
            }

            const id = randomUUID();
            const now = new Date().toISOString();
            const item = {
              ...body,
              pk: tableConfig.pk,
              sk: id,
              id,
              createdAt: now,
              updatedAt: now,
              作成日時: now,
              更新日時: now
            };

            await docClient.send(new PutCommand({
              TableName: TABLE_NAME,
              Item: item
            }));

            await writeAuditLog('CREATE', { tableIndex, tableName: tableConfig.name, itemId: id });
            return createResponse(201, item);
          } catch (error) {
            console.error('Create operation error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }

        case 'PUT':
          if (!itemId) {
            return createResponse(400, { error: 'Item ID is required for update' });
          }
          
          if (!hasPermission(userRole, tableConfig.pk, 'update')) {
            return createResponse(403, { error: 'Insufficient permissions' });
          }

          try {
            const body = JSON.parse(event.body || '{}');
            const now = new Date().toISOString();
            
            const existingItem = await docClient.send(new GetCommand({
              TableName: TABLE_NAME,
              Key: { pk: tableConfig.pk, sk: itemId }
            }));
            
            if (!existingItem.Item) {
              return createResponse(404, { error: 'Item not found' });
            }

            const updatedItem = {
              ...existingItem.Item,
              ...body,
              pk: tableConfig.pk,
              sk: itemId,
              id: itemId,
              updatedAt: now,
              更新日時: now
            };

            await docClient.send(new PutCommand({
              TableName: TABLE_NAME,
              Item: updatedItem
            }));

            await writeAuditLog('UPDATE', { tableIndex, tableName: tableConfig.name, itemId });
            return createResponse(200, updatedItem);
          } catch (error) {
            console.error('Update operation error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }

        case 'DELETE':
          if (!itemId) {
            return createResponse(400, { error: 'Item ID is required for delete' });
          }
          
          if (!hasPermission(userRole, tableConfig.pk, 'delete')) {
            return createResponse(403, { error: 'Insufficient permissions' });
          }

          try {
            const existingItem = await docClient.send(new GetCommand({
              TableName: TABLE_NAME,
              Key: { pk: tableConfig.pk, sk: itemId }
            }));
            
            if (!existingItem.Item) {
              return createResponse(404, { error: 'Item not found' });
            }

            await docClient.send(new DeleteCommand({
              TableName: TABLE_NAME,
              Key: { pk: tableConfig.pk, sk: itemId }
            }));

            await writeAuditLog('DELETE', { tableIndex, tableName: tableConfig.name, itemId });
            return createResponse(200, { message: 'Item deleted successfully' });
          } catch (error) {
            console.error('Delete operation error:', error);
            return createResponse(500, { error: 'Internal server error' });
          }

        default:
          return createResponse(405, { error: 'Method not allowed' });
      }
    }

    return createResponse(404, { error: 'Endpoint not found' });
  } catch (error) {
    console.error('Handler error:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
};