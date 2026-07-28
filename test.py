from openrouter import OpenRouter
import os

with OpenRouter(api_key=os.getenv("OPENROUTER_API_KEY")) as client:
    response = client.chat.send(
        model="meta-llama/llama-3.3-70b-instruct",
                      messages=[
            {"role": "user", "content": "Explain quantum computing in one sentence."}
        ],
    )

    print(response.choices[0].message.content)