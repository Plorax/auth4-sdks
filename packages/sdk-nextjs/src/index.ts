"use client";

// Client entry: Auth4Provider, useUser and getAccessToken for client components. Nothing here sees
// a token except getAccessToken(), and only when the application turns on /auth/access-token.
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import type { AccessTokenResponse, User } from "./types.ts";

export type { AccessTokenResponse, User } from "./types.ts";

export interface UserState {
  /** The signed-in user, null when signed out, undefined while loading. */
  user: User | null | undefined;
  isLoading: boolean;
  error: Error | null;
  /** Fetch the profile again, for example after a sign-in in another tab. */
  invalidate: () => Promise<void>;
}

const UserContext = createContext<UserState | null>(null);

async function fetchProfile(profileUrl: string): Promise<User | null> {
  const response = await fetch(profileUrl, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (response.status === 204 || response.status === 401) return null;
  if (!response.ok) throw new Error(`The profile route returned HTTP ${response.status}.`);
  return (await response.json()) as User;
}

function useProfile(initialUser: User | null | undefined, profileUrl: string): UserState {
  const [user, setUser] = useState<User | null | undefined>(initialUser);
  const [error, setError] = useState<Error | null>(null);
  const invalidate = useCallback(async () => {
    try {
      setUser(await fetchProfile(profileUrl));
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error("Unable to load the profile."));
      setUser(null);
    }
  }, [profileUrl]);
  useEffect(() => {
    // A user rendered on the server is already current; otherwise ask the profile route.
    if (initialUser === undefined) void invalidate();
  }, [initialUser, invalidate]);
  return { user, isLoading: user === undefined && error === null, error, invalidate };
}

export interface Auth4ProviderProps {
  /**
   * The user from `(await auth4.getSession())?.user` in a server layout, so client components
   * render signed in without a request. Pass null for signed out; leave it out to fetch.
   */
  user?: User | null;
  /** Default /auth/profile. */
  profileUrl?: string;
  children?: ReactNode;
}

/** Shares one profile request between every useUser() below it. */
export function Auth4Provider({
  user,
  profileUrl = "/auth/profile",
  children,
}: Auth4ProviderProps): ReactNode {
  const state = useProfile(user, profileUrl);
  return createElement(UserContext.Provider, { value: state }, children);
}

/** The signed-in user. Works without Auth4Provider too, with its own profile request. */
export function useUser(options: { profileUrl?: string } = {}): UserState {
  const context = useContext(UserContext);
  const own = useProfile(context ? null : undefined, options.profileUrl ?? "/auth/profile");
  return context ?? own;
}

export class AccessTokenRequestError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(`The access-token route answered ${status} (${code}).`);
    this.name = "AccessTokenRequestError";
  }
}

/**
 * Reads the access token from /auth/access-token, which the application must turn on with
 * `enableAccessTokenEndpoint`. Prefer calling your APIs from the server so tokens stay there.
 */
export async function getAccessToken(options: { url?: string } = {}): Promise<AccessTokenResponse> {
  const response = await fetch(options.url ?? "/auth/access-token", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok || typeof body?.["token"] !== "string") {
    throw new AccessTokenRequestError(
      typeof body?.["error"] === "string" ? body["error"] : "unavailable",
      response.status,
    );
  }
  return body as unknown as AccessTokenResponse;
}
