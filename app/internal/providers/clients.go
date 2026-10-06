package providers

import (
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/openai/openai-go/v3"
	openaioption "github.com/openai/openai-go/v3/option"
)

func NewOpenAI(apiKey string) openai.Client {
	return openai.NewClient(openaioption.WithAPIKey(apiKey))
}

func NewOpenAICompatible(apiKey, baseURL string) openai.Client {
	return openai.NewClient(openaioption.WithAPIKey(apiKey), openaioption.WithBaseURL(baseURL))
}

func NewAnthropic(apiKey string) anthropic.Client {
	return anthropic.NewClient(option.WithAPIKey(apiKey))
}
