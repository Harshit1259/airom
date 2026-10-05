"""OpenAI usage fixture — positive and negative cases."""
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def ask(question: str) -> str:
    # airom: openai/chat-call
    resp = client.chat.completions.create(
        # airom: openai/model-literal
        model="gpt-4o",
        temperature=0.2,
        max_tokens=1024,
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content


def reason(question: str) -> str:
    # airom: openai/model-literal
    payload = {"model": "o3-mini", "input": question}
    return client.responses.create(**payload).output_text



def media() -> None:
    """Non-chat hosted models: image, video, speech, moderation, agentic, legacy."""
    # airom: openai/media-model-literal
    client.images.generate(model="dall-e-3", prompt="a cat")
    # airom: openai/media-model-literal
    client.videos.create(model="sora-2-pro", prompt="a cat")
    # airom: openai/media-model-literal
    client.audio.transcriptions.create(model="whisper-1", file=None)
    # airom: openai/media-model-literal
    client.moderations.create(model="omni-moderation-latest", input="x")
    # airom: openai/media-model-literal
    client.moderations.create(model="text-moderation-007", input="x")
    # airom: openai/media-model-literal
    client.responses.create(model="computer-use-preview", input="x")
    # airom: openai/media-model-literal
    client.responses.create(model="codex-mini-latest", input="x")
    # airom: openai/media-model-literal
    client.completions.create(model="babbage-002", prompt="x")

# Negative cases below.

# airom-ok: openai/media-model-literal
local_stt = "whisper-large-v3"        # open weights, run locally — not OpenAI-hosted

# airom-ok: openai/media-model-literal
third_party_image = {"model": "dall-e-mini"}   # a different project reusing the name

# airom-ok: openai/media-model-literal
sora_service = {"model": "sora-app"}  # no digit after the family prefix

# airom-ok: openai/model-literal
# model="gpt-4o-mini"   (this line is a comment — never scanned)

# airom-ok: openai/model-literal
adapter = "gpt-neo-125m"  # not an OpenAI id and not in a model= position

# airom-ok: openai/chat-call
existing = client.chat.completions.retrieve("resp_123")
