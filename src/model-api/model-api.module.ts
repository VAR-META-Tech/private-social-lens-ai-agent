import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { OpenAiService } from './services/openai.service';
import { ClaudeService } from './services/claude.service';
import { GeminiService } from './services/gemini.service';
import { ModelApiFactoryService } from './services/model-api-factory.service';
import openaiConfig from './config/openai.config';
import claudeConfig from './config/claude.config';
import geminiConfig from './config/gemini.config';

@Module({
  imports: [
    ConfigModule.forFeature(openaiConfig),
    ConfigModule.forFeature(claudeConfig),
    ConfigModule.forFeature(geminiConfig),
  ],
  providers: [
    OpenAiService,
    ClaudeService,
    GeminiService,
    ModelApiFactoryService,
  ],
  exports: [ModelApiFactoryService],
})
export class ModelApiModule {}
