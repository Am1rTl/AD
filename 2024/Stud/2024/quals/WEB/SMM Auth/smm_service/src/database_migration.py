from .models import Messages, Base
from .database import SessionLocal, engine


def init_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    session = SessionLocal()

    message_1 = Messages(
        title="Анонсы статей из блога",
        description="Анонс должен заинтриговать читателя и мотивировать перейти на сайт, чтобы почитать материал полностью.",
    )

    message_2 = Messages(
        title="Краткая выжимка из статьи",
        description="Расскажите тезисно, о чем материал — получится полноценный пост.",
    )

    message_3 = Messages(
        title="Чек-лист.",
        description="Напишите по пунктам инструкцию для подписчиков, которая может их заинтересовать.",
    )

    message_4 = Messages(
        title="Отрывок из статьи",
        description="Выберите самый интригующий ее отрывок, опубликуйте и дайте ссылку на весь материал.",
    )

    message_5 = Messages(
        title="Экспертное мнение",
        description="Делитесь своим мнением по актуальной теме. Так вы сможете позиционировать себя в качестве эксперта рынка.",
    )

    session.add_all([message_1, message_2, message_3, message_4, message_5])
    session.commit()
