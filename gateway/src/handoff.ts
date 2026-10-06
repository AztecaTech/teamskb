const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function privateHandoffMessage(teamsAppId: string, publicOrigin: string): string {
  if (!guidPattern.test(teamsAppId)) throw new Error('Teams app ID must be a GUID');

  const origin = new URL(publicOrigin);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('Public origin must be an HTTPS origin');
  }

  const link = new URL(`https://teams.microsoft.com/l/entity/${teamsAppId}/assistant`);
  link.searchParams.set('webUrl', origin.origin);
  link.searchParams.set('label', 'IQ Knowledge Assistant');
  return `Open [IQ Knowledge Assistant](${link.toString()}) to ask privately. I do not return answers in chats or channels.`;
}

export async function sendPrivateHandoff(
  send: (message: string) => Promise<unknown>,
  teamsAppId: string,
  publicOrigin: string,
): Promise<void> {
  await send(privateHandoffMessage(teamsAppId, publicOrigin));
}
