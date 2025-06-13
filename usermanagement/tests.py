from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import JustPackUser
from .permissions import IsPaxPermission

class IsPaxPermissionTests(APITestCase):
    def setUp(self):
        # Create some sample users
        self.pax_user = JustPackUser.objects.create(
            username='pax_user', email='pax_user@example.com', type='Pax', is_verified=True
        )
        self.unverified_user = JustPackUser.objects.create(
            username='unverified_user', email='unverified_user@example.com', type='Pax', is_verified=False
        )
        self.non_pax_user = JustPackUser.objects.create(
            username='non_pax_user', email='non_pax_user@example.com', type='NonPax', is_verified=True
        )
        self.anonymous_user = None

    def test_pax_user_has_permission(self):
        """
        Ensure that a verified Pax user has permission.
        """
        self.client.force_authenticate(user=self.pax_user)
        url = reverse('protected-view')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_unverified_user_has_no_permission(self):
        """
        Ensure that an unverified Pax user has no permission.
        """
        self.client.force_authenticate(user=self.unverified_user)
        url = reverse('protected-view')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_non_pax_user_has_no_permission(self):
        """
        Ensure that a non-Pax user has no permission.
        """
        self.client.force_authenticate(user=self.non_pax_user)
        url = reverse('protected-view')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_anonymous_user_has_no_permission(self):
        """
        Ensure that an anonymous user has no permission.
        """
        self.client.force_authenticate(user=None)
        url = reverse('protected-view')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)