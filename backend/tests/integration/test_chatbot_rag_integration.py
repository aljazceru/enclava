"""
Integration tests for chatbot with RAG integration

Tests:
- Chatbot creation with RAG collection
- Chatbot chat with RAG context injection
- RAG document retrieval in chatbot
- Chatbot without RAG collection
- Chatbot RAG with empty collection
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from qdrant_client import QdrantClient
import uuid

from app.models.chatbot import ChatbotInstance, ChatbotConversation, ChatbotMessage


@pytest_asyncio.fixture
async def test_chatbot(test_db: AsyncSession, test_user: dict) -> ChatbotInstance:
    """Create a test chatbot instance without RAG."""
    chatbot = ChatbotInstance(
        id=str(uuid.uuid4()),
        name="Test Chatbot",
        description="A test chatbot for integration testing",
        config={
            "model": "gpt-3.5-turbo",
            "temperature": 0.7,
            "system_message": "You are a helpful assistant.",
            "max_tokens": 1000
        },
        created_by=test_user["id"],
        is_active=True
    )
    test_db.add(chatbot)
    await test_db.commit()
    await test_db.refresh(chatbot)
    return chatbot


@pytest_asyncio.fixture
async def test_chatbot_with_rag(
    test_db: AsyncSession,
    test_user: dict,
    test_qdrant_collection: str
) -> ChatbotInstance:
    """Create a test chatbot instance with RAG collection."""
    chatbot = ChatbotInstance(
        id=str(uuid.uuid4()),
        name="Test RAG Chatbot",
        description="A test chatbot with RAG for integration testing",
        config={
            "model": "gpt-3.5-turbo",
            "temperature": 0.7,
            "system_message": "You are a helpful assistant with access to documents.",
            "max_tokens": 1000,
            "rag_enabled": True,
            "rag_collection": test_qdrant_collection,
            "rag_top_k": 3
        },
        created_by=test_user["id"],
        is_active=True
    )
    test_db.add(chatbot)
    await test_db.commit()
    await test_db.refresh(chatbot)
    return chatbot


@pytest_asyncio.fixture
async def test_conversation(
    test_db: AsyncSession,
    test_chatbot: ChatbotInstance,
    test_user: dict
) -> ChatbotConversation:
    """Create a test conversation."""
    conversation = ChatbotConversation(
        id=str(uuid.uuid4()),
        chatbot_id=test_chatbot.id,
        user_id=test_user["id"],
        title="Test Conversation",
        is_active=True,
        context_data={}
    )
    test_db.add(conversation)
    await test_db.commit()
    await test_db.refresh(conversation)
    return conversation


@pytest.mark.asyncio
async def test_chatbot_creation_without_rag(test_db: AsyncSession, test_chatbot: ChatbotInstance):
    """Test creating a chatbot without RAG collection."""
    assert test_chatbot.id is not None, "Chatbot should be created"
    assert test_chatbot.name == "Test Chatbot"
    assert test_chatbot.is_active is True

    # Config should not have RAG settings
    config = test_chatbot.config
    assert "rag_enabled" not in config or not config.get("rag_enabled"), \
        "Chatbot should not have RAG enabled"


@pytest.mark.asyncio
async def test_chatbot_creation_with_rag(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance,
    test_qdrant_collection: str
):
    """Test creating a chatbot with RAG collection."""
    assert test_chatbot_with_rag.id is not None, "Chatbot should be created"
    assert test_chatbot_with_rag.name == "Test RAG Chatbot"
    assert test_chatbot_with_rag.is_active is True

    # Config should have RAG settings
    config = test_chatbot_with_rag.config
    assert config.get("rag_enabled") is True, "Chatbot should have RAG enabled"
    assert config.get("rag_collection") == test_qdrant_collection, \
        "Chatbot should be linked to RAG collection"
    assert config.get("rag_top_k") == 3, "RAG top_k should be configured"


@pytest.mark.asyncio
async def test_chatbot_conversation_creation(
    test_db: AsyncSession,
    test_conversation: ChatbotConversation,
    test_chatbot: ChatbotInstance
):
    """Test creating a conversation for a chatbot."""
    assert test_conversation.id is not None, "Conversation should be created"
    assert test_conversation.chatbot_id == test_chatbot.id, \
        "Conversation should be linked to chatbot"
    assert test_conversation.is_active is True


@pytest.mark.asyncio
async def test_chatbot_message_storage(
    test_db: AsyncSession,
    test_conversation: ChatbotConversation
):
    """Test storing messages in a conversation."""
    # Create user message
    user_message = ChatbotMessage(
        id=str(uuid.uuid4()),
        conversation_id=test_conversation.id,
        role="user",
        content="Hello, can you help me?",
        message_metadata={}
    )
    test_db.add(user_message)

    # Create assistant message
    assistant_message = ChatbotMessage(
        id=str(uuid.uuid4()),
        conversation_id=test_conversation.id,
        role="assistant",
        content="Hello! I'd be happy to help you.",
        message_metadata={"model": "gpt-3.5-turbo", "tokens": 15}
    )
    test_db.add(assistant_message)

    await test_db.commit()
    await test_db.refresh(user_message)
    await test_db.refresh(assistant_message)

    # Verify messages
    assert user_message.id is not None
    assert assistant_message.id is not None
    assert user_message.role == "user"
    assert assistant_message.role == "assistant"


@pytest.mark.asyncio
async def test_chatbot_message_with_rag_sources(
    test_db: AsyncSession,
    test_conversation: ChatbotConversation
):
    """Test storing messages with RAG source information."""
    # Create message with RAG sources
    message_with_sources = ChatbotMessage(
        id=str(uuid.uuid4()),
        conversation_id=test_conversation.id,
        role="assistant",
        content="Based on the documentation, here's the answer...",
        message_metadata={"model": "gpt-3.5-turbo", "tokens": 50},
        sources=[
            {
                "document_id": "doc1",
                "chunk_id": "chunk1",
                "score": 0.95,
                "content": "Relevant document content..."
            },
            {
                "document_id": "doc2",
                "chunk_id": "chunk2",
                "score": 0.87,
                "content": "More relevant content..."
            }
        ]
    )
    test_db.add(message_with_sources)
    await test_db.commit()
    await test_db.refresh(message_with_sources)

    # Verify sources are stored
    assert message_with_sources.sources is not None
    assert len(message_with_sources.sources) == 2
    assert message_with_sources.sources[0]["document_id"] == "doc1"
    assert message_with_sources.sources[0]["score"] == 0.95


@pytest.mark.asyncio
async def test_chatbot_rag_retrieval_with_documents(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance,
    qdrant_client: QdrantClient,
    test_qdrant_collection: str
):
    """Test RAG document retrieval when documents exist in collection."""
    from qdrant_client.models import PointStruct, Distance, VectorParams
    import numpy as np

    # Add some test documents to the collection
    points = [
        PointStruct(
            id=1,
            vector=np.random.rand(1536).tolist(),
            payload={
                "content": "This is a test document about Python programming.",
                "document_id": "doc1",
                "chunk_id": "chunk1"
            }
        ),
        PointStruct(
            id=2,
            vector=np.random.rand(1536).tolist(),
            payload={
                "content": "This document explains FastAPI framework.",
                "document_id": "doc2",
                "chunk_id": "chunk1"
            }
        )
    ]

    qdrant_client.upsert(
        collection_name=test_qdrant_collection,
        points=points
    )

    # Verify documents were added
    collection_info = qdrant_client.get_collection(test_qdrant_collection)
    assert collection_info.points_count == 2, "Documents should be added to collection"

    # Test retrieval (would need actual RAG service integration)
    config = test_chatbot_with_rag.config
    assert config.get("rag_collection") == test_qdrant_collection


@pytest.mark.asyncio
async def test_chatbot_without_rag_collection(
    test_db: AsyncSession,
    test_chatbot: ChatbotInstance
):
    """Test chatbot operation without RAG collection."""
    # Chatbot should work fine without RAG
    config = test_chatbot.config
    assert not config.get("rag_enabled"), "RAG should not be enabled"

    # Can still create conversations and messages
    conversation = ChatbotConversation(
        id=str(uuid.uuid4()),
        chatbot_id=test_chatbot.id,
        user_id=test_chatbot.created_by,
        is_active=True
    )
    test_db.add(conversation)
    await test_db.commit()
    await test_db.refresh(conversation)

    assert conversation.id is not None


@pytest.mark.asyncio
async def test_chatbot_rag_with_empty_collection(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance,
    qdrant_client: QdrantClient,
    test_qdrant_collection: str
):
    """Test chatbot with RAG when collection is empty."""
    # Verify collection is empty
    collection_info = qdrant_client.get_collection(test_qdrant_collection)
    assert collection_info.points_count == 0, "Collection should be empty"

    # Chatbot should still be created successfully
    assert test_chatbot_with_rag.id is not None
    config = test_chatbot_with_rag.config
    assert config.get("rag_enabled") is True


@pytest.mark.asyncio
async def test_chatbot_conversation_history_retrieval(
    test_db: AsyncSession,
    test_conversation: ChatbotConversation
):
    """Test retrieving conversation history."""
    # Add multiple messages
    messages = []
    for i in range(5):
        user_msg = ChatbotMessage(
            id=str(uuid.uuid4()),
            conversation_id=test_conversation.id,
            role="user",
            content=f"User message {i}"
        )
        assistant_msg = ChatbotMessage(
            id=str(uuid.uuid4()),
            conversation_id=test_conversation.id,
            role="assistant",
            content=f"Assistant response {i}"
        )
        messages.extend([user_msg, assistant_msg])

    test_db.add_all(messages)
    await test_db.commit()

    # Retrieve conversation with messages
    from sqlalchemy import select
    stmt = select(ChatbotMessage).where(
        ChatbotMessage.conversation_id == test_conversation.id
    ).order_by(ChatbotMessage.timestamp)

    result = await test_db.execute(stmt)
    retrieved_messages = result.scalars().all()

    assert len(retrieved_messages) == 10, "Should retrieve all messages"


@pytest.mark.asyncio
async def test_chatbot_rag_context_injection(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance
):
    """Test that RAG context is properly configured for injection."""
    config = test_chatbot_with_rag.config

    # Verify RAG configuration
    assert config.get("rag_enabled") is True
    assert "rag_collection" in config
    assert "rag_top_k" in config

    # The actual context injection would happen in the chat service
    # This test verifies the configuration is ready


@pytest.mark.asyncio
async def test_chatbot_multiple_conversations(
    test_db: AsyncSession,
    test_chatbot: ChatbotInstance,
    test_user: dict
):
    """Test managing multiple conversations for one chatbot."""
    # Create multiple conversations
    conversations = []
    for i in range(3):
        conv = ChatbotConversation(
            id=str(uuid.uuid4()),
            chatbot_id=test_chatbot.id,
            user_id=test_user["id"],
            title=f"Conversation {i}",
            is_active=True
        )
        conversations.append(conv)

    test_db.add_all(conversations)
    await test_db.commit()

    # Verify all conversations are created
    from sqlalchemy import select
    stmt = select(ChatbotConversation).where(
        ChatbotConversation.chatbot_id == test_chatbot.id
    )

    result = await test_db.execute(stmt)
    retrieved_convs = result.scalars().all()

    assert len(retrieved_convs) == 3, "Should have 3 conversations"


@pytest.mark.asyncio
async def test_chatbot_cascade_delete_conversations(
    test_db: AsyncSession,
    test_chatbot: ChatbotInstance,
    test_user: dict
):
    """Test that deleting chatbot cascades to conversations."""
    # Create conversation
    conversation = ChatbotConversation(
        id=str(uuid.uuid4()),
        chatbot_id=test_chatbot.id,
        user_id=test_user["id"],
        is_active=True
    )
    test_db.add(conversation)
    await test_db.commit()

    conversation_id = conversation.id

    # Delete chatbot
    await test_db.delete(test_chatbot)
    await test_db.commit()

    # Verify conversation is also deleted (cascade)
    from sqlalchemy import select
    stmt = select(ChatbotConversation).where(
        ChatbotConversation.id == conversation_id
    )
    result = await test_db.execute(stmt)
    deleted_conv = result.scalar_one_or_none()

    assert deleted_conv is None, "Conversation should be cascade deleted"


@pytest.mark.asyncio
async def test_chatbot_rag_top_k_configuration(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance
):
    """Test RAG top_k configuration."""
    config = test_chatbot_with_rag.config

    # Verify top_k is configurable
    assert "rag_top_k" in config
    top_k = config.get("rag_top_k")
    assert isinstance(top_k, int)
    assert top_k > 0


@pytest.mark.asyncio
async def test_chatbot_analytics_tracking(
    test_db: AsyncSession,
    test_chatbot: ChatbotInstance,
    test_user: dict
):
    """Test chatbot analytics event tracking."""
    from app.models.chatbot import ChatbotAnalytics

    # Create analytics event
    analytics = ChatbotAnalytics(
        chatbot_id=test_chatbot.id,
        user_id=test_user["id"],
        event_type="message_sent",
        event_data={"message_length": 50},
        response_time_ms=150,
        token_count=20,
        cost_cents=1,
        model_used="gpt-3.5-turbo",
        rag_used=False
    )
    test_db.add(analytics)
    await test_db.commit()
    await test_db.refresh(analytics)

    assert analytics.id is not None
    assert analytics.event_type == "message_sent"


@pytest.mark.asyncio
async def test_chatbot_analytics_with_rag(
    test_db: AsyncSession,
    test_chatbot_with_rag: ChatbotInstance,
    test_user: dict
):
    """Test chatbot analytics tracking with RAG usage."""
    from app.models.chatbot import ChatbotAnalytics

    # Create analytics event with RAG
    analytics = ChatbotAnalytics(
        chatbot_id=test_chatbot_with_rag.id,
        user_id=test_user["id"],
        event_type="response_generated",
        event_data={"sources_retrieved": 3},
        response_time_ms=300,
        token_count=50,
        cost_cents=3,
        model_used="gpt-3.5-turbo",
        rag_used=True
    )
    test_db.add(analytics)
    await test_db.commit()
    await test_db.refresh(analytics)

    assert analytics.rag_used is True
    assert analytics.event_data.get("sources_retrieved") == 3
