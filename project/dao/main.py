from typing import Optional, List

from sqlalchemy import desc
from werkzeug.exceptions import NotFound

from project.dao.base import BaseDAO, T
from project.models import *


class GenresDAO(BaseDAO[Genre]):
    __model__ = Genre


class DirectorsDAO(BaseDAO[Director]):
    __model__ = Director


class MoviesDAO(BaseDAO[Movie]):
    __model__ = Movie

    def get_all_order_by (self, page: Optional[int] = None, filter = None) -> List[T]:
        stmt = self._db_session.query(self.__model__)
        if filter:
            stmt = stmt.order_by(desc(self.__model__.year))

        if page:
            try:
                return stmt.paginate(page, self._items_per_page).items
            except NotFound:
                return []
        return stmt.all()



class UsersDAO(BaseDAO[User]):
    __model__ = User

    def create(self, login, password):
        try:
            self._db_session.add(
                User(
                    email=login,
                    password=hash(password)
                )
            )
            self._db_session.commit()
            print("User is added")
        except Exception as e:
            print(e)
            self._db_session.rollback()

    def get_token(self, login, password_hash):
        try:
            stmt = self._db_session.query(self.__model__).filter(self._db_session.query(self.__model__.email==login)).one()
            return stmt
        except Exception as e:
            print(e)
            return {}





