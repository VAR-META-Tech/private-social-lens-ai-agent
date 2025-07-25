import { Injectable, BadRequestException } from '@nestjs/common';
import { ModelApiService } from '../interfaces/model-api.interface';
import { OpenAiService } from './openai.service';
import { ClaudeService } from './claude.service';
import { GeminiService } from './gemini.service';
import { ModelProvider } from '../enums/model-provider.enum';

@Injectable()
export class ModelApiFactoryService {
  constructor(
    private readonly openAiService: OpenAiService,
    private readonly claudeService: ClaudeService,
    private readonly geminiService: GeminiService,
  ) {}

  getModelService(provider: ModelProvider): ModelApiService {
    switch (provider) {
      case ModelProvider.OPENAI:
        return this.openAiService;
      case ModelProvider.CLAUDE:
        return this.claudeService;
      case ModelProvider.GEMINI:
        return this.geminiService;
      default:
        throw new BadRequestException(
          `Unsupported model provider: ${provider}`,
        );
    }
  }

  getAvailableProviders(): ModelProvider[] {
    return Object.values(ModelProvider);
  }
}
