import unittest
from unittest.mock import AsyncMock, MagicMock
from src.repository import contacts as contacts_repository
from datetime import date, timedelta
from src.schemas.contact import ContactCreate, ContactUpdate

class TestContactRepository(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.db = AsyncMock()
        self.user_id = 1
        self.contact_id = 10
        self.contact_data = ContactCreate(
            first_name="John",
            last_name="Doe",
            email="john@example.com",
            phone="1234567890",
            birthday=date.today(),
            extra_info="Test info",

        )
        self.updated_data = ContactUpdate(
            first_name="Johnny",
            last_name="Doe",
            email="john@example.com",
            phone="1234567890",
            birthday=date.today(),
            extra_info="Updated"
        )

    async def test_create_contact(self):
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()
        self.db.add = MagicMock()
        contact = await contacts_repository.create_contact(self.db, self.contact_data, self.user_id)
        self.assertIsNotNone(contact)
        self.db.add.assert_called_once()
        self.db.commit.assert_called_once()
        self.assertEqual(contact.first_name, self.contact_data.first_name)
        self.assertEqual(contact.owner_id, self.user_id)

    async def test_get_contact(self):
        mock_contact_instance = MagicMock()
        mock_contact_instance.id = self.contact_id
        mock_contact_instance.first_name = "John"
        mock_contact_instance.last_name = "Doe"
        mock_contact_instance.email = "john@example.com"
        mock_contact_instance.phone = "1234567890"
        mock_contact_instance.birthday = date.today()
        mock_contact_instance.extra_info = "Test info"
        mock_contact_instance.owner_id = self.user_id

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_contact_instance
        self.db.execute.return_value = mock_result
        result = await contacts_repository.get_contact(self.db, self.contact_id, self.user_id)
        self.assertEqual(result.id, self.contact_id)
        self.assertEqual(result.email, "john@example.com")

    async def test_get_contacts(self):
        mock_contact1 = MagicMock()
        mock_contact1.id = 1
        mock_contact1.first_name = "Jane"
        mock_contact1.last_name = "Smith"
        mock_contact1.email = "jane@example.com"
        mock_contact1.phone = "9876543210"
        mock_contact1.birthday = date.today()
        mock_contact1.extra_info = "Friend"
        mock_contact1.owner_id = 1

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_contact1]
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        self.db.execute.return_value = mock_result
        result = await contacts_repository.get_contacts(self.db, self.user_id)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].email, "jane@example.com")

    async def test_update_contact(self):
        mock_contact_to_update = MagicMock()
        mock_contact_to_update.id = self.contact_id
        mock_contact_to_update.first_name = "John"
        mock_contact_to_update.last_name = "Doe"
        mock_contact_to_update.email = "john@example.com"
        mock_contact_to_update.phone = "1234567890"
        mock_contact_to_update.birthday = date.today()
        mock_contact_to_update.extra_info = "Test info"
        mock_contact_to_update.owner_id = self.user_id

        mock_get_contact_result = MagicMock()
        mock_get_contact_result.scalar_one_or_none.return_value = mock_contact_to_update
        self.db.execute.return_value = mock_get_contact_result
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()
        result = await contacts_repository.update_contact(self.db, self.contact_id, self.updated_data, self.user_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.first_name, self.updated_data.first_name)
        self.assertEqual(result.extra_info, self.updated_data.extra_info)
        self.db.commit.assert_called_once()
        self.db.refresh.assert_called_once_with(mock_contact_to_update)


    async def test_delete_contact(self):
        mock_contact_to_delete = MagicMock()
        mock_contact_to_delete.id = self.contact_id
        mock_contact_to_delete.first_name = "John"
        mock_contact_to_delete.last_name = "Doe"
        mock_contact_to_delete.email = "john@example.com"
        mock_contact_to_delete.phone = "1234567890"
        mock_contact_to_delete.birthday = date.today()
        mock_contact_to_delete.extra_info = "Test info"
        mock_contact_to_delete.owner_id = self.user_id

        mock_get_contact_result = MagicMock()
        mock_get_contact_result.scalar_one_or_none.return_value = mock_contact_to_delete
        self.db.execute.return_value = mock_get_contact_result
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()

        result = await contacts_repository.delete_contact(self.db, self.contact_id, self.user_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.contact_id)
        self.db.commit.assert_called_once()
        self.db.delete.assert_called_once_with(mock_contact_to_delete)


    async def test_search_contacts(self):
        mock_contact_found = MagicMock()
        mock_contact_found.id = 1
        mock_contact_found.first_name = "John"
        mock_contact_found.last_name = "Smith"
        mock_contact_found.email = "john.smith@example.com"
        mock_contact_found.phone = "9876543210"
        mock_contact_found.birthday = date.today()
        mock_contact_found.extra_info = "Friend"
        mock_contact_found.owner_id = 1

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_contact_found]
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        self.db.execute.return_value = mock_result
        result = await contacts_repository.search_contacts(self.db, "john", self.user_id)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].first_name, "John")

    async def test_get_upcoming_birthdays(self):
        mock_contact_birthday = MagicMock()
        mock_contact_birthday.id = 1
        mock_contact_birthday.first_name = "John"
        mock_contact_birthday.last_name = "Doe"
        mock_contact_birthday.email = "jane.doe@example.com"
        mock_contact_birthday.phone = "9876543210"
        mock_contact_birthday.birthday = date.today() + timedelta(days=3)  # Cumpleaños en los próximos 7 días
        mock_contact_birthday.extra_info = "Friend"
        mock_contact_birthday.owner_id = 1

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_contact_birthday]
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        self.db.execute.return_value = mock_result
        result = await contacts_repository.get_upcoming_birthdays(self.db, self.user_id)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].first_name, "John")


if __name__ == "__main__":
    unittest.main()