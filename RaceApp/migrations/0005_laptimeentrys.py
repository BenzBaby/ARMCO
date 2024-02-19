# Generated by Django 4.2.5 on 2024-02-18 06:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('RaceApp', '0004_laptimeentry'),
    ]

    operations = [
        migrations.CreateModel(
            name='LapTimeEntrys',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rider_name', models.CharField(max_length=100)),
                ('total_lap_time', models.CharField(max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
