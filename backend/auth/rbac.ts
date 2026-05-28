export interface User {
  id: string;
  role: 'admin' | 'operator' | 'viewer';
  permissions: string[];
}

export const ROLES = {
  admin: {
    permissions: [
      'resources:read',
      'resources:write',
      'resources:delete',
      'users:read',
      'users:write',
      'users:delete',
      'projects:read',
      'projects:write',
      'projects:delete',
      'data:read',
      'data:write',
      'data:delete',
      'audit:read',
      'sustainability:read',
      'sustainability:write',
      'sustainability:delete',
      'privacy:read',
      'privacy:write',
      'privacy:delete',
      'analysis:read',
      'analysis:write',
      'analysis:delete',
      'notifications:read',
      'notifications:write',
      'notifications:delete',
      'virtual:read',
      'virtual:write',
      'virtual:delete',
      'bulk:import'
    ]
  },
  operator: {
    permissions: [
      'resources:read',
      'resources:write',
      'users:read',
      'projects:read',
      'projects:write',
      'data:read',
      'data:write',
      'sustainability:read',
      'sustainability:write',
      'privacy:read',
      'privacy:write',
      'analysis:read',
      'analysis:write',
      'notifications:read',
      'notifications:write',
      'virtual:read',
      'virtual:write',
      'bulk:import'
    ]
  },
  viewer: {
    permissions: [
      'resources:read',
      'users:read',
      'projects:read',
      'data:read',
      'sustainability:read',
      'privacy:read',
      'analysis:read',
      'notifications:read',
      'virtual:read'
    ]
  }
} as const;

export function hasPermission(user: User, permission: string): boolean {
  return user.permissions.includes(permission);
}

export function checkPermission(user: User, permission: string): void {
  if (!hasPermission(user, permission)) {
    throw new Error(`Insufficient permissions. Required: ${permission}`);
  }
}

export function getUserFromEvent(event: any): User {
  const claims = event.requestContext?.authorizer?.claims;
  if (!claims) {
    throw new Error('No authorization claims found');
  }
  
  const role = claims['custom:role'] || 'viewer';
  const userId = claims.sub;
  
  if (!['admin', 'operator', 'viewer'].includes(role)) {
    throw new Error('Invalid role');
  }
  
  return {
    id: userId,
    role: role as 'admin' | 'operator' | 'viewer',
    permissions: ROLES[role as keyof typeof ROLES].permissions
  };
}