# Generated by Django 4.2.5 on 2024-02-15 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('RaceApp', '0002_remove_userprofile_total_race_time_totaltime'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='total_race_time',
            field=models.CharField(default='00:00:00', max_length=100),
        ),
        migrations.DeleteModel(
            name='totaltime',
        ),
    ]