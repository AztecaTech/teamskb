import { sendPrivateHandoff } from './handoff.js';

const MAX_REPLY_BYTES = 20_000;
const encoder = new TextEncoder();

function limitUtf8(text: string, maxBytes: number): string {
  let bytes = 0;
  const characters: string[] = [];
  for (const character of text) {
    const size = encoder.encode(character).length;
    if (bytes + size > maxBytes) break;
    characters.push(character);
    bytes += size;
  }
  return characters.join('');
}

function safeSourceUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return '';
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname && !url.username && !url.password ? url.toString() : '';
  } catch {
    return '';
  }
}

function safeSourceName(value: unknown): string {
  if (typeof value !== 'string') return 'Source';
  return value
    .replace(/\b(?:https?:\/\/|www\.)\S+/gi, 'link omitted')
    .replace(/[\r\n\u0000-\u001F]/g, ' ')
    .replace(/[\\[\]()_*~`!>#|]/g, ' ')
    .trim()
    .slice(0, 200) || 'Source';
}

function safeAnswerText(value: string): string {
  return value
    .replace(/^\s{0,3}\[[^\]]+\]:\s*\S+.*$/gm, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\[[^\]]*\]/g, '$1')
    .replace(/<[^>]*>/g, '')
    .replace(/\b(?:[a-z][a-z0-9+.-]{1,31}:\/\/|www\.)\S+/gi, '[link omitted]')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}

type BotMessageContext = {
  activity: { conversation: { conversationType?: unknown }; text?: string };
  signin: (options: { oauthCardText: string; signInButtonText: string }) => Promise<string | undefined>;
  send: (message: string) => Promise<unknown>;
};

export function createBotMessageHandler(
  teamsAppId: string,
  publicOrigin: string,
  fetcher: typeof fetch = fetch,
) {
  return async ({ activity, signin, send }: BotMessageContext): Promise<void> => {
    if (activity.conversation.conversationType !== 'personal') {
      await sendPrivateHandoff(send, teamsAppId, publicOrigin);
      return;
    }

    const question = activity.text?.trim();
    if (!question) {
      await send('Send a question about your connected work sources.');
      return;
    }
    if (new TextEncoder().encode(question).length > 12_000) {
      await send('That question is too long. Shorten it and try again.');
      return;
    }

    const token = await signin({
      oauthCardText: 'Sign in to search your connected work sources.',
      signInButtonText: 'Sign in',
    });
    if (!token) return;

    try {
      const response = await fetcher('http://app:8080/api/ask', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ question }),
        signal: AbortSignal.timeout(155_000),
        cache: 'no-store',
      });
      if (!response.ok) {
        await send(response.status === 429
          ? 'Your daily question limit has been reached. Try again tomorrow.'
          : 'I could not answer that right now. Try again in the private knowledge tab.');
        return;
      }
      const result = await response.json() as {
        answer?: unknown;
        clarification?: { kind?: unknown; question?: unknown; candidates?: unknown };
        sources?: Array<{ name?: unknown; url?: unknown }>;
      };
      let answer: string;
      if (typeof result.answer === 'string') {
        answer = safeAnswerText(result.answer);
      } else if (result.clarification && result.clarification.kind === 'ambiguous_entity' && typeof result.clarification.question === 'string' && Array.isArray(result.clarification.candidates)) {
        const prompt = safeAnswerText(result.clarification.question).slice(0, 1000);
        const candidates = result.clarification.candidates.slice(0, 5).map((item) => {
          if (!item || typeof item !== 'object') return '';
          const candidate = item as { id?: unknown; displayName?: unknown };
          const name = typeof candidate.displayName === 'string' ? safeSourceName(candidate.displayName) : '';
          const id = typeof candidate.id === 'string' ? safeSourceName(candidate.id) : '';
          return name && id ? `- ${name} (${id})` : name ? `- ${name}` : '';
        }).filter(Boolean);
        answer = candidates.length ? `${prompt}\n\nMatches:\n${candidates.join('\n')}` : prompt;
      } else {
        throw new Error('invalid answer response');
      }
      const citations = Array.isArray(result.sources)
        ? result.sources.slice(0, 6).map((source) => {
            const name = safeSourceName(source.name);
            const url = safeSourceUrl(source.url);
            return url ? `- ${name}: ${url}` : `- ${name}`;
          })
        : [];
      const reply = citations.length ? `${answer}\n\nSources:\n${citations.join('\n')}` : answer;
      await send(limitUtf8(reply, MAX_REPLY_BYTES));
    } catch {
      await send('I could not answer that right now. Try again in the private knowledge tab.');
    }
  };
}
