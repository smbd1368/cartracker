def generate_string_representation(instance, excluded_field_types=None):
    """
    Generate a string representation of a Django model instance,
    excluding specific field types.

    :param instance: The model instance to represent as a string.
    :param excluded_field_types: List of field types to exclude from the representation.
    :return: A string representation of the instance.
    """
    if excluded_field_types is None:
        excluded_field_types = ['ManyToManyField', 'TextField', 'ImageField', 'FileField']

    field_values = []
    
    for field in instance._meta.fields:
        # Exclude specific field types
        if field.get_internal_type() not in excluded_field_types:
            value = getattr(instance, field.name)
            field_values.append(str(value) if value is not None else 'NULL')
    
    # Join all field values into a single string
    return ', '.join(field_values)
