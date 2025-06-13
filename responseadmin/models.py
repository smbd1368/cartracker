from django.db import models

class BaseModel(models.Model):
    class Meta:
        abstract = True  # Ensures this model is not created as a table in the database.

    def __str__(self):
        # Get all fields of the model
        for field in self._meta.get_fields():
            if isinstance(field, models.CharField):
                return str(getattr(self, field.name))
        return super().__str__()  # Fallback if no CharField is found
