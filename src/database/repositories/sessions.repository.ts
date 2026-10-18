import { Injectable } from '@nestjs/common';
import { BaseRepository } from './base.repository';

export interface SessionRecord {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  device_info: string | null;
  ip_address: string | null;
  expires_at: string;
  created_at: string;
  token_family: string;
  revoked_at: string | null;
}

/**
 * Encapsulates all Supabase queries for the `sessions` table.
 */
@Injectable()
export class SessionsRepository extends BaseRepository {
  /**
   * Finds a session by its refresh token hash.
   */
  async findByHash(hash: string): Promise<SessionRecord | null> {
    const { data, error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .select(
        'id, user_id, refresh_token_hash, device_info, ip_address, expires_at, created_at, token_family, revoked_at',
      )
      .eq('refresh_token_hash', hash)
      .maybeSingle();

    this.throwOnError(error);
    return data;
  }

  /**
   * Creates a new session record.
   */
  async create(session: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: string;
    tokenFamily?: string;
    deviceInfo?: string;
    ipAddress?: string;
  }): Promise<SessionRecord> {
    const insertData: {
      user_id: string;
      refresh_token_hash: string;
      expires_at: string;
      token_family?: string;
      device_info?: string;
      ip_address?: string;
    } = {
      user_id: session.userId,
      refresh_token_hash: session.refreshTokenHash,
      expires_at: session.expiresAt,
    };
    if (session.tokenFamily) {
      insertData.token_family = session.tokenFamily;
    }
    if (session.deviceInfo) {
      insertData.device_info = session.deviceInfo;
    }
    if (session.ipAddress) {
      insertData.ip_address = session.ipAddress;
    }

    const { data, error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .insert(insertData)
      .select('*')
      .single();

    this.throwOnError(error);
    return data;
  }

  /**
   * Deletes a session by its ID.
   */
  async delete(id: string): Promise<void> {
    const { error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .delete()
      .eq('id', id);

    this.throwOnError(error);
  }

  /**
   * Deletes a session by its refresh token hash.
   */
  async deleteByHash(hash: string): Promise<void> {
    const { error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .delete()
      .eq('refresh_token_hash', hash);

    this.throwOnError(error);
  }

  /**
   * Revokes all sessions belonging to the given token family.
   * This is used to invalidate the family if a reused refresh token is detected.
   */
  async revokeFamily(tokenFamily: string): Promise<void> {
    const { error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('token_family', tokenFamily);

    this.throwOnError(error);
  }

  /**
   * Marks a session as used/rotated by setting `revoked_at`. The row is kept so a
   * later replay of its refresh token can be detected.
   * Only succeeds if the session was not already revoked; returns false otherwise
   * (i.e. a concurrent rotation already consumed it).
   */
  async markRotated(id: string): Promise<boolean> {
    const { data, error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', id)
      .is('revoked_at', null)
      .select('id');

    this.throwOnError(error);
    return Array.isArray(data) && data.length > 0;
  }

  /**
   * Finds a session by ID.
   */
  async findById(id: string): Promise<SessionRecord | null> {
    const { data, error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .select(
        'id, user_id, refresh_token_hash, device_info, ip_address, expires_at, created_at, token_family, revoked_at',
      )
      .eq('id', id)
      .maybeSingle();

    this.throwOnError(error);
    return data;
  }

  /**
   * Lists active (not revoked, not expired) sessions for a user, newest first.
   */
  async findActiveByUserId(userId: string): Promise<SessionRecord[]> {
    const { data, error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .select(
        'id, user_id, refresh_token_hash, device_info, ip_address, expires_at, created_at, token_family, revoked_at',
      )
      .eq('user_id', userId)
      .is('revoked_at', null)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false });

    this.throwOnError(error);
    return data ?? [];
  }

  /**
   * Revokes every non-revoked session of a user (logout from all devices).
   */
  async revokeAllByUserId(userId: string): Promise<void> {
    const { error } = await this.supabaseService
      .getServiceRoleClient()
      .from('sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('user_id', userId)
      .is('revoked_at', null);

    this.throwOnError(error);
  }
}
