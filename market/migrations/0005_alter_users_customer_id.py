# Generated by Django 4.2.6 on 2024-02-24 22:03

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("market", "0004_alter_users_customer_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="users",
            name="customer_id",
            field=models.CharField(blank=True, max_length=25, null=True),
        ),
    ]
