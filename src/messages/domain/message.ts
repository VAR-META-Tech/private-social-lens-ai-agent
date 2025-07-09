import { Conversation } from '../../conversations/domain/conversation';
import { ApiProperty } from '@nestjs/swagger';

export class Message {
  @ApiProperty({
    type: () => String,
    nullable: false,
  })
  content: string;

  @ApiProperty({
    type: () => String,
    nullable: false,
  })
  role: string;

  @ApiProperty({
    type: () => Conversation,
    nullable: false,
  })
  conversation: Conversation;

  @ApiProperty({
    type: String,
  })
  id: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}
